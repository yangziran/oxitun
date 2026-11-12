use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 初始拷贝缓冲区大小：64KB，保证低流量/短连接的首字节延迟（TTFB）
const INITIAL_BUF_SIZE: usize = 64 * 1024;
/// 升档后的拷贝缓冲区上限：256KB，高吞吐场景下减少 syscall 次数
const MAX_BUF_SIZE: usize = 256 * 1024;
/// 连续读满当前缓冲区的次数阈值：达到即证明连接处于满载状态，升档至 256KB
const UPGRADE_THRESHOLD: usize = 4;

/// 拷贝缓冲区封装，维护单向数据流的读取和写入状态
struct CopyBuffer {
    /// 标志数据源是否已经读到 EOF
    read_done: bool,
    /// 标志缓冲区内是否有残留数据需要向写入端 flush
    need_flush: bool,
    /// 标志写入端是否已完成半关闭（shutdown 只执行一次）
    shutdown_done: bool,
    /// 当前已读出（消费）的缓冲区偏移量
    pos: usize,
    /// 缓冲区内有效数据的总长度
    cap: usize,
    /// 该缓冲区历史传输的总字节数
    amt: u64,
    /// 堆分配的字节数组，初始 64KB，连续读满后可升档至 256KB
    buf: Box<[u8]>,
    /// 连续读满当前缓冲区的次数（短读/EOF/挂起会重置为 0），
    /// 达到阈值即升档，用于识别满载的高吞吐连接
    consecutive_full_reads: usize,
    /// 连续满块次数已达阈值，但当前缓冲区尚有未 flush 的数据，
    /// 待缓冲区排空（下一次读取前）再扩容，避免丢弃已读数据
    upgrade_pending: bool,
}

impl CopyBuffer {
    /// 创建一个新的全零初始化的 64KB 拷贝缓冲区
    fn new() -> Self {
        Self {
            read_done: false,
            need_flush: false,
            shutdown_done: false,
            pos: 0,
            cap: 0,
            amt: 0,
            buf: vec![0; INITIAL_BUF_SIZE].into_boxed_slice(),
            consecutive_full_reads: 0,
            upgrade_pending: false,
        }
    }

    /// 根据本次读取结果更新升档状态：
    /// - 恰好读满当前缓冲区（满载）→ 计数 +1，达到阈值且未达 256KB 上限时置升档标记；
    /// - 短读（n < buf.len()）→ 连接不饱和，计数清零。
    ///
    /// 实际扩容在缓冲区排空后由 apply_upgrade 执行，避免丢弃尚未写出的数据。
    fn update_tier(&mut self, n: usize) {
        if n == self.buf.len() && n > 0 {
            self.consecutive_full_reads += 1;
            if self.consecutive_full_reads >= UPGRADE_THRESHOLD && self.buf.len() < MAX_BUF_SIZE {
                self.upgrade_pending = true;
                // 256KB 封顶，升档后重新计数
                self.consecutive_full_reads = 0;
            }
        } else {
            self.consecutive_full_reads = 0;
        }
    }

    /// 缓冲区已排空（下一次读取前）时执行实际扩容。
    /// 升档后缓冲区保持 256KB 直至连接结束（每方向最多 256KB，内存开销可接受），
    /// 不主动缩容以避免长连接空闲-再满载时的反复 realloc。
    fn apply_upgrade(&mut self) {
        if self.upgrade_pending && self.buf.len() < MAX_BUF_SIZE {
            self.buf = vec![0; MAX_BUF_SIZE].into_boxed_slice();
        }
        self.upgrade_pending = false;
    }

    fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<std::io::Result<u64>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        loop {
            if self.cap == self.pos {
                if self.read_done {
                    if self.need_flush {
                        std::task::ready!(writer.as_mut().poll_flush(cx))?;
                        self.need_flush = false;
                    }
                    // 读到 EOF 且缓冲已 flush 后，半关闭写端，
                    // 让对端感知写方向关闭（避免 HTTP/1.0、SMTP 等协议永久死等）
                    if !self.shutdown_done {
                        std::task::ready!(writer.as_mut().poll_shutdown(cx))?;
                        self.shutdown_done = true;
                    }
                    return Poll::Ready(Ok(self.amt));
                }

                // 缓冲区已排空（cap == pos），可安全执行延迟的升档扩容
                self.apply_upgrade();
                let mut buf = ReadBuf::new(&mut self.buf);
                match reader.as_mut().poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(())) => {
                        let n = buf.filled().len();
                        if n == 0 {
                            // EOF：连接读取结束，重置计数（连接结束后缓冲区随即释放）
                            self.read_done = true;
                            self.consecutive_full_reads = 0;
                        } else {
                            self.pos = 0;
                            self.cap = n;
                            self.update_tier(n);
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        // 读挂起说明连接当前不饱和，重置连续满块计数
                        self.consecutive_full_reads = 0;
                        if self.need_flush {
                            std::task::ready!(writer.as_mut().poll_flush(cx))?;
                            self.need_flush = false;
                        }
                        return Poll::Pending;
                    }
                }
            }

            while self.pos < self.cap {
                match writer
                    .as_mut()
                    .poll_write(cx, &self.buf[self.pos..self.cap])
                {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "向写入端写入了零字节数据",
                        )));
                    }
                    Poll::Ready(Ok(n)) => {
                        self.pos += n;
                        self.amt += n as u64;
                        self.need_flush = true;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }
}

/// 双向拷贝 Future，管理 A 和 B 两端的双向通信流
struct BidirectionalCopy<'a, A: ?Sized, B: ?Sized> {
    /// 通信端 A (通常是本地客户端流)
    a: &'a mut A,
    /// 通信端 B (通常是远端代理流)
    b: &'a mut B,
    /// 从 A 到 B 的传输缓冲区
    a_to_b: CopyBuffer,
    /// 从 B 到 A 的传输缓冲区
    b_to_a: CopyBuffer,
}

impl<'a, A, B> Future for BidirectionalCopy<'a, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = std::io::Result<(u64, u64)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // 方向完成的判断必须同时满足：读到 EOF、缓冲消费完毕、
        // flush 与 shutdown 均已执行完成。否则 poll_flush/poll_shutdown
        // 返回 Pending 后（read_done=true 且 pos==cap），下一轮会误判该方向
        // 已完成而永久跳过半关闭，导致 Future 提前 Ready。
        let mut a_to_b_done = self.a_to_b.read_done
            && self.a_to_b.pos == self.a_to_b.cap
            && !self.a_to_b.need_flush
            && self.a_to_b.shutdown_done;
        let mut b_to_a_done = self.b_to_a.read_done
            && self.b_to_a.pos == self.b_to_a.cap
            && !self.b_to_a.need_flush
            && self.b_to_a.shutdown_done;
        let BidirectionalCopy {
            a,
            b,
            a_to_b,
            b_to_a,
        } = &mut *self;

        // 处理 A 端向 B 端的单向拷贝
        if !a_to_b_done {
            match a_to_b.poll_copy(cx, Pin::new(&mut **a), Pin::new(&mut **b)) {
                Poll::Ready(Ok(_)) => a_to_b_done = true,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }

        // 处理 B 端向 A 端的单向拷贝
        if !b_to_a_done {
            match b_to_a.poll_copy(cx, Pin::new(&mut **b), Pin::new(&mut **a)) {
                Poll::Ready(Ok(_)) => b_to_a_done = true,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }

        // 当双方的 EOF 及 Flush 均完成时，视为双向传输结束
        if a_to_b_done && b_to_a_done {
            Poll::Ready(Ok((a_to_b.amt, b_to_a.amt)))
        } else {
            Poll::Pending
        }
    }
}

/// 执行两个异步读写流之间的双向零延迟桥接传输，返回各自传输的总字节数。
///
/// 缓冲区自适应：初始 64KB 保证低流量/短连接的首字节延迟（TTFB）；
/// 当某个方向连续读满当前缓冲区达到阈值时，升档至 256KB 以减少高吞吐
/// 场景下的 syscall 次数，256KB 封顶。当两端均断开或引发 I/O 错误时结束。
pub async fn copy_bidirectional_64k<A, B>(a: &mut A, b: &mut B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    BidirectionalCopy {
        a,
        b,
        a_to_b: CopyBuffer::new(),
        b_to_a: CopyBuffer::new(),
    }
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    /// 定长数据 reader：每次 poll_read 尽力填满 ReadBuf 提供的全部容量，
    /// 总预算耗尽后返回 EOF。记录每次实际填充的字节数以观察块大小变化。
    /// 填充内容为按全局偏移生成的递增字节序列（(offset + i) as u8），
    /// 使测试可严格校验字节流连续性（升档边界错位会立即暴露）。
    struct ChunkedReader {
        remaining: usize,
        offset: usize,
        observed_chunks: std::cell::RefCell<Vec<usize>>,
    }

    impl ChunkedReader {
        fn new(total: usize) -> Self {
            Self {
                remaining: total,
                offset: 0,
                observed_chunks: std::cell::RefCell::new(Vec::new()),
            }
        }
    }

    impl AsyncRead for ChunkedReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.remaining == 0 {
                return Poll::Ready(Ok(())); // EOF
            }
            let n = this.remaining.min(buf.remaining());
            let base = this.offset;
            let mut chunk = [0u8; 4096];
            let mut written = 0;
            while written < n {
                let m = (n - written).min(chunk.len());
                for (i, b) in chunk[..m].iter_mut().enumerate() {
                    *b = (base + written + i) as u8;
                }
                buf.put_slice(&chunk[..m]);
                written += m;
            }
            this.offset += n;
            this.remaining -= n;
            this.observed_chunks.borrow_mut().push(n);
            Poll::Ready(Ok(()))
        }
    }

    /// 单次 poll CopyBuffer，原样返回 Poll 结果。
    /// 供 Pending 路径测试自行检查中间状态并推进 reader/writer 状态机。
    fn poll_once<R, W>(
        cb: &mut CopyBuffer,
        reader: &mut R,
        writer: &mut W,
    ) -> Poll<std::io::Result<u64>>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        cb.poll_copy(&mut cx, Pin::new(reader), Pin::new(writer))
    }

    /// 单次 poll 驱动 CopyBuffer 直至传输完成，返回总字节数。
    /// 测试 reader/writer 均立即返回 Ready，poll_copy 内部循环可一次跑完；
    /// 若返回 Pending 说明测试构造有误（空 waker 永远不会被唤醒）。
    fn drive_copy<R, W>(cb: &mut CopyBuffer, reader: &mut R, writer: &mut W) -> u64
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        match poll_once(cb, reader, writer) {
            Poll::Ready(Ok(amt)) => amt,
            Poll::Ready(Err(e)) => panic!("拷贝失败: {e}"),
            Poll::Pending => panic!("测试 reader/writer 不应返回 Pending"),
        }
    }

    /// 循环 poll 驱动 CopyBuffer 直至 Ready，容忍中途 Pending。
    /// 依赖测试 reader/writer 内部状态机在每次 poll 间自行推进
    /// （测试内唤醒自身，无需真实 waker 调度）。
    fn drive_copy_allow_pending<R, W>(cb: &mut CopyBuffer, reader: &mut R, writer: &mut W) -> u64
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            match poll_once(cb, reader, writer) {
                Poll::Ready(Ok(amt)) => return amt,
                Poll::Ready(Err(e)) => panic!("拷贝失败: {e}"),
                Poll::Pending => {}
            }
        }
    }

    /// 小流量场景：读端只提供 100 字节即 EOF，
    /// 验证功能正确且缓冲区始终保持 64KB 初始档位（不升档、不牺牲 TTFB）。
    #[test]
    fn small_traffic_stays_at_64k() {
        let mut cb = CopyBuffer::new();
        assert_eq!(cb.buf.len(), INITIAL_BUF_SIZE);
        assert_eq!(cb.consecutive_full_reads, 0);

        let mut reader = ChunkedReader::new(100);
        let mut writer = tokio::io::sink();

        let amt = drive_copy(&mut cb, &mut reader, &mut writer);
        assert_eq!(amt, 100);
        assert_eq!(cb.buf.len(), INITIAL_BUF_SIZE);
        assert_eq!(cb.consecutive_full_reads, 0);
        assert!(cb.read_done && cb.shutdown_done);
    }

    /// 大流量升档：连续读满 64KB 块 4 次（约 256KB，证明连接满载）后，
    /// 验证缓冲区升档至 256KB，且后续读取使用 256KB 大块。
    #[test]
    fn sustained_full_reads_upgrade_to_256k() {
        let mut cb = CopyBuffer::new();

        // 4 个满 64KB 块触发升档 + 升档后 1 个满 256KB 块
        let mut reader = ChunkedReader::new(4 * 64 * 1024 + 256 * 1024);
        let mut writer = tokio::io::sink();

        let amt = drive_copy(&mut cb, &mut reader, &mut writer);
        assert_eq!(amt, (4 * 64 * 1024 + 256 * 1024) as u64);
        assert_eq!(cb.buf.len(), MAX_BUF_SIZE);

        let chunks = reader.observed_chunks.borrow();
        assert_eq!(chunks.len(), 5);
        assert!(chunks[..4].iter().all(|&n| n == 64 * 1024));
        assert_eq!(chunks[4], 256 * 1024);
    }

    /// 升档边界：仅 3 次连续满块（未达阈值）+ 1 次短读，
    /// 短读重置计数，缓冲区不得升档。
    #[test]
    fn short_read_resets_upgrade_counter() {
        let mut cb = CopyBuffer::new();

        // 3 个满 64KB 块 + 1 个 100 字节短读
        let mut reader = ChunkedReader::new(3 * 64 * 1024 + 100);
        let mut writer = tokio::io::sink();

        let amt = drive_copy(&mut cb, &mut reader, &mut writer);
        assert_eq!(amt, (3 * 64 * 1024 + 100) as u64);
        assert_eq!(cb.buf.len(), INITIAL_BUF_SIZE);

        let chunks = reader.observed_chunks.borrow();
        assert_eq!(chunks.len(), 4);
        assert!(chunks[..3].iter().all(|&n| n == 64 * 1024));
        assert_eq!(chunks[3], 100);
    }

    /// 状态机 reader：前 pending_at 次 poll_read 正常返回满块，
    /// 第 pending_at + 1 次返回 Pending（唤醒自身），之后恢复满块直至预算耗尽。
    /// 用于验证读方向 Pending 会重置连续满块计数。
    struct PendingOnceReader {
        inner: ChunkedReader,
        polls: usize,
        pending_at: usize,
    }

    impl AsyncRead for PendingOnceReader {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            this.polls += 1;
            if this.polls == this.pending_at + 1 {
                // 唤醒自身以保证被再次 poll（测试驱动循环不依赖真实 waker）
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Pin::new(&mut this.inner).poll_read(cx, buf)
        }
    }

    /// 读 Pending 重置升档计数：前 3 次满块使计数到 3，第 4 次读取返回 Pending
    /// 后计数必须清零；恢复满读后需重新累计 4 次满块才触发升档。
    #[test]
    fn read_pending_resets_upgrade_counter() {
        // 3 块（Pending 前） + 4 块（Pending 后重新累计触发升档） + 1 个升档后的 256KB 块
        let total = 7 * 64 * 1024 + 256 * 1024;
        let mut cb = CopyBuffer::new();
        let mut reader = PendingOnceReader {
            inner: ChunkedReader::new(total),
            polls: 0,
            pending_at: 3, // 第 4 次 poll_read 返回 Pending
        };
        let mut writer = tokio::io::sink();

        // 第一次驱动：读满 3 块后第 4 次读取 Pending，poll_copy 应挂起且计数清零
        match poll_once(&mut cb, &mut reader, &mut writer) {
            Poll::Pending => {}
            other => panic!("预期 Pending，实际 {other:?}"),
        }
        assert_eq!(cb.consecutive_full_reads, 0);
        assert_eq!(cb.buf.len(), INITIAL_BUF_SIZE);
        assert!(!cb.upgrade_pending);

        // 继续驱动至完成：Pending 之后需重新累计 4 次满块才升档
        let amt = drive_copy_allow_pending(&mut cb, &mut reader, &mut writer);
        assert_eq!(amt, total as u64);
        assert_eq!(cb.buf.len(), MAX_BUF_SIZE);

        let chunks = reader.inner.observed_chunks.borrow();
        // 前 7 块均为 64KB（若 Pending 未重置计数，第 5 块就会升档为 256KB），
        // 第 8 块才是升档后的 256KB
        assert_eq!(chunks.len(), 8);
        assert!(chunks[..7].iter().all(|&n| n == 64 * 1024));
        assert_eq!(chunks[7], 256 * 1024);
    }

    /// 状态机 writer：前 stall_after 次 poll_write 全部接受，
    /// 随后 stall_left 次返回 Pending（唤醒自身），之后恢复全部接受。
    /// 记录全部写入数据以便校验。
    struct StallWriter {
        accepted: usize,
        stall_after: usize,
        stall_left: usize,
        written: Vec<u8>,
    }

    impl AsyncWrite for StallWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if this.accepted >= this.stall_after && this.stall_left > 0 {
                this.stall_left -= 1;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.accepted += 1;
            this.written.extend_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// 写出 Pending 期间升档悬挂：第 4 次满读置位 upgrade_pending 后，
    /// 该块写出连续返回 Pending，期间缓冲区未排空，apply_upgrade 不得执行
    /// （buf 保持 64KB）；排空后才升到 256KB 且后续读取使用 256KB 大块。
    #[test]
    fn write_pending_defers_upgrade_until_drained() {
        // 4 个满 64KB 块触发升档 + 升档后 1 个满 256KB 块
        let total = 4 * 64 * 1024 + 256 * 1024;
        let mut cb = CopyBuffer::new();
        let mut reader = ChunkedReader::new(total);
        let mut writer = StallWriter {
            accepted: 0,
            stall_after: 3, // 前 3 块写出正常
            stall_left: 2,  // 第 4 块写出连续 2 次 Pending
            written: Vec::new(),
        };

        // 第一次驱动：读满 4 块（计数达阈值置位 upgrade_pending），
        // 但第 4 块写出 Pending，缓冲区未排空
        match poll_once(&mut cb, &mut reader, &mut writer) {
            Poll::Pending => {}
            other => panic!("预期 Pending，实际 {other:?}"),
        }
        assert!(cb.upgrade_pending);
        // 升档标记已置位但数据未排空，apply_upgrade 不得执行
        assert_eq!(cb.buf.len(), INITIAL_BUF_SIZE);
        assert_eq!(cb.cap - cb.pos, 64 * 1024);

        // 第二次驱动仍处于写出停滞期：升档继续保持悬挂，buf 仍为 64KB
        match poll_once(&mut cb, &mut reader, &mut writer) {
            Poll::Pending => {}
            other => panic!("预期 Pending，实际 {other:?}"),
        }
        assert!(cb.upgrade_pending);
        assert_eq!(cb.buf.len(), INITIAL_BUF_SIZE);

        // 第三次驱动：停滞结束，第 4 块排空后 apply_upgrade 执行，升至 256KB
        let amt = drive_copy_allow_pending(&mut cb, &mut reader, &mut writer);
        assert_eq!(amt, total as u64);
        assert_eq!(cb.buf.len(), MAX_BUF_SIZE);

        let chunks = reader.observed_chunks.borrow();
        assert_eq!(chunks.len(), 5);
        assert!(chunks[..4].iter().all(|&n| n == 64 * 1024));
        assert_eq!(chunks[4], 256 * 1024);

        // 写出数据完整且与全局递增序列一致
        assert_eq!(writer.written.len(), total);
        assert!(
            writer
                .written
                .iter()
                .enumerate()
                .all(|(i, &b)| b == i as u8)
        );
    }

    /// 升档边界字节连续性：第 4 次满块触发升档，校验升档前后写出的字节流
    /// 与全局递增序列严格一致（旧实现全填 0xAB，边界错位无法被发现）。
    #[test]
    fn upgrade_boundary_bytes_are_contiguous() {
        // 4 个满 64KB 块（触发升档） + 1 个满 256KB 块 + 12345 字节尾块
        let total = 4 * 64 * 1024 + 256 * 1024 + 12345;
        let mut cb = CopyBuffer::new();
        let mut reader = ChunkedReader::new(total);
        let mut writer: Vec<u8> = Vec::new();

        let amt = drive_copy(&mut cb, &mut reader, &mut writer);
        assert_eq!(amt, total as u64);
        assert_eq!(cb.buf.len(), MAX_BUF_SIZE);

        // 确认升档确实发生在传输中途：前 4 块 64KB，随后 256KB 块，最后短读尾块
        let chunks = reader.observed_chunks.borrow();
        assert_eq!(chunks.len(), 6);
        assert!(chunks[..4].iter().all(|&n| n == 64 * 1024));
        assert_eq!(chunks[4], 256 * 1024);
        assert_eq!(chunks[5], 12345);

        // 全量字节与全局递增序列严格比对，升档边界（第 256KB 处）错位会立即暴露
        assert_eq!(writer.len(), total);
        assert!(writer.iter().enumerate().all(|(i, &b)| b == i as u8));
    }

    /// 复合流：读方向来自指定的 ChunkedReader（大流量升档 + EOF），
    /// 写方向代理到内部 duplex 端，用于验证升档后 EOF 仍正确传播 shutdown。
    struct ReaderOverDuplex {
        reader: ChunkedReader,
        inner: tokio::io::DuplexStream,
    }

    impl AsyncRead for ReaderOverDuplex {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.reader).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for ReaderOverDuplex {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, data)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// 升档后 EOF 与 shutdown 语义：满载传输触发 64KB → 256KB 升档后，
    /// 对端仍应收到全部数据 + EOF（复用 half_close 测试模式）。
    #[tokio::test]
    async fn upgrade_then_eof_completes_shutdown() {
        let (mut a_client, a_server_duplex) = duplex(1024);
        let (mut b_client, mut b_server) = duplex(1024);

        let total = 4 * 64 * 1024 + 128 * 1024;
        let mut a_server = ReaderOverDuplex {
            reader: ChunkedReader::new(total),
            inner: a_server_duplex,
        };

        let handle =
            tokio::spawn(async move { copy_bidirectional_64k(&mut a_server, &mut b_server).await });

        // B 侧应读到全部数据后收到 EOF（升档不影响半关闭传播）
        let mut buf = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            b_client.read_to_end(&mut buf),
        )
        .await
        .expect("读取超时：升档后 EOF/shutdown 未正确传播")
        .unwrap();
        assert_eq!(buf.len(), total);
        // ChunkedReader 填充全局递增序列，逐字节比对验证无错位
        assert!(buf.iter().enumerate().all(|(i, &b)| b == i as u8));

        // B 侧回应并半关闭，A 侧（经复合流代理的 duplex）应读到回应 + EOF
        b_client.write_all(b"resp").await.unwrap();
        b_client.shutdown().await.unwrap();

        let mut buf2 = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            a_client.read_to_end(&mut buf2),
        )
        .await
        .expect("读取超时")
        .unwrap();
        assert_eq!(buf2, b"resp");

        let (a_to_b, b_to_a) = handle.await.unwrap().unwrap();
        assert_eq!(a_to_b, total as u64);
        assert_eq!(b_to_a, 4);
    }

    /// 半关闭语义：一端写完数据并 shutdown 写端后，
    /// 桥接对端的读取方应收到数据 + EOF（旧实现只 flush 不 shutdown，会永久死等）。
    #[tokio::test]
    async fn half_close_propagates_write_shutdown() {
        let (mut a_client, mut a_server) = duplex(1024);
        let (mut b_client, mut b_server) = duplex(1024);

        let handle =
            tokio::spawn(async move { copy_bidirectional_64k(&mut a_server, &mut b_server).await });

        // A 侧发送请求后半关闭写端
        a_client.write_all(b"req").await.unwrap();
        a_client.shutdown().await.unwrap();

        // B 侧应读到数据后收到 EOF（证明桥接对 b_server 执行了 shutdown）
        let mut buf = Vec::new();
        b_client.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"req");

        // B 侧回应并半关闭，A 侧应读到回应 + EOF
        b_client.write_all(b"resp").await.unwrap();
        b_client.shutdown().await.unwrap();

        let mut buf2 = Vec::new();
        a_client.read_to_end(&mut buf2).await.unwrap();
        assert_eq!(buf2, b"resp");

        let (a_to_b, b_to_a) = handle.await.unwrap().unwrap();
        assert_eq!(a_to_b, 3);
        assert_eq!(b_to_a, 4);
    }

    /// 包装流：首次 poll_shutdown 先唤醒自身再返回 Pending，
    /// 模拟异步写端在半关闭时需要多次 poll 才能完成的场景。
    struct DelayedShutdown<S> {
        inner: S,
        delayed: bool,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for DelayedShutdown<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for DelayedShutdown<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, data)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            if !self.delayed {
                // 第一次调用返回 Pending，但必须唤醒 waker 以保证被再次 poll
                self.delayed = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// poll_shutdown 首次返回 Pending 时，桥接不得在下一轮误判方向完成而跳过
    /// shutdown。验证 shutdown 最终确实执行（对端读到 EOF）且尾部数据完整。
    #[tokio::test]
    async fn shutdown_pending_is_retried_until_complete() {
        let (mut a_client, a_server) = duplex(1024);
        let (mut b_client, b_server) = duplex(1024);

        let mut a_server = DelayedShutdown {
            inner: a_server,
            delayed: false,
        };
        let mut b_server = DelayedShutdown {
            inner: b_server,
            delayed: false,
        };

        let handle =
            tokio::spawn(async move { copy_bidirectional_64k(&mut a_server, &mut b_server).await });

        // A 侧发送数据后半关闭写端
        a_client.write_all(b"req").await.unwrap();
        a_client.shutdown().await.unwrap();

        // B 侧应读到完整数据后收到 EOF（证明延迟的 shutdown 被重试并最终执行）
        let mut buf = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            b_client.read_to_end(&mut buf),
        )
        .await
        .expect("读取超时：shutdown 未被重试执行")
        .unwrap();
        assert_eq!(buf, b"req");

        // B 侧回应并半关闭，A 侧应读到回应 + EOF
        b_client.write_all(b"resp").await.unwrap();
        b_client.shutdown().await.unwrap();

        let mut buf2 = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            a_client.read_to_end(&mut buf2),
        )
        .await
        .expect("读取超时：shutdown 未被重试执行")
        .unwrap();
        assert_eq!(buf2, b"resp");

        let (a_to_b, b_to_a) = handle.await.unwrap().unwrap();
        assert_eq!(a_to_b, 3);
        assert_eq!(b_to_a, 4);
    }
}
