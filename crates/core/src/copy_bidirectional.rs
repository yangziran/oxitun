use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct CopyBuffer {
    read_done: bool,
    need_flush: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
}

impl CopyBuffer {
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
                            "write zero byte into writer",
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

struct BidirectionalCopy<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_to_b: CopyBuffer,
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

        if !a_to_b_done {
            match a_to_b.poll_copy(cx, Pin::new(&mut **a), Pin::new(&mut **b)) {
                Poll::Ready(Ok(_)) => a_to_b_done = true,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }

        if !b_to_a_done {
            match b_to_a.poll_copy(cx, Pin::new(&mut **b), Pin::new(&mut **a)) {
                Poll::Ready(Ok(_)) => b_to_a_done = true,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }

        if a_to_b_done && b_to_a_done {
            Poll::Ready(Ok((a_to_b.amt, b_to_a.amt)))
        } else {
            Poll::Pending
        }
    }
}

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
