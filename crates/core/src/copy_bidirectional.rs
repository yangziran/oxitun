use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 拷贝缓冲区封装，维护单向数据流的读取和写入状态
struct CopyBuffer {
    /// 标志数据源是否已经读到 EOF
    read_done: bool,
    /// 标志缓冲区内是否有残留数据需要向写入端 flush
    need_flush: bool,
    /// 当前已读出（消费）的缓冲区偏移量
    pos: usize,
    /// 缓冲区内有效数据的总长度
    cap: usize,
    /// 该缓冲区历史传输的总字节数
    amt: u64,
    /// 堆分配的字节数组，默认大小为 64KB
    buf: Box<[u8]>,
}

impl CopyBuffer {
    /// 创建一个新的全零初始化的 64KB 拷贝缓冲区
    fn new() -> Self {
        Self {
            read_done: false,
            need_flush: false,
            pos: 0,
            cap: 0,
            amt: 0,
            buf: vec![0; 65536].into_boxed_slice(),
        }
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
                    return Poll::Ready(Ok(self.amt));
                }

                let mut buf = ReadBuf::new(&mut self.buf);
                match reader.as_mut().poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(())) => {
                        let n = buf.filled().len();
                        if n == 0 {
                            self.read_done = true;
                        } else {
                            self.pos = 0;
                            self.cap = n;
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        if self.need_flush {
                            std::task::ready!(writer.as_mut().poll_flush(cx))?;
                            self.need_flush = false;
                        }
                        return Poll::Pending;
                    }
                }
            }

            while self.pos < self.cap {
                match writer.as_mut().poll_write(cx, &self.buf[self.pos..self.cap]) {
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
        let mut a_to_b_done = self.a_to_b.read_done && self.a_to_b.pos == self.a_to_b.cap;
        let mut b_to_a_done = self.b_to_a.read_done && self.b_to_a.pos == self.b_to_a.cap;
        let BidirectionalCopy { a, b, a_to_b, b_to_a } = &mut *self;

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

/// 执行两个异步读写流之间高效的 64KB 块双向零延迟桥接传输
/// 当两端均断开或引发 I/O 错误时结束，返回各自传输的总字节数。
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
