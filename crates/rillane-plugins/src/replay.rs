//! 首块探测回放 io（plugin-loader.md §2.2）：探测字节先回放、后续透传。
//!
//! `IoStream` blanket impl（rillane-core lib.rs:18）对本类型自动生效——
//! 装回 `BoxedIo` 无需任何适配。

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use rillane_core::IoStream;

pub struct ReplayIo {
    replay: Vec<u8>,
    pos: usize,
    inner: Box<dyn IoStream>,
}

impl ReplayIo {
    pub fn new(replay: Vec<u8>, inner: Box<dyn IoStream>) -> Self {
        Self {
            replay,
            pos: 0,
            inner,
        }
    }
}

impl AsyncRead for ReplayIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // 回放未尽：从探测字节拷贝（单次至多 buf 容量），拷完再透传
        if self.pos < self.replay.len() {
            let n = (self.replay.len() - self.pos).min(buf.remaining());
            let end = self.pos + n;
            buf.put_slice(&self.replay[self.pos..end]);
            self.pos = end;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReplayIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 回放与透传的边界：回放尽后必须交还 inner。DuplexStream 经 blanket
    /// impl 即 IoStream，直接入 ReplayIo；主路径覆盖见 lib.rs §4.1 用例。
    #[tokio::test]
    async fn replay_then_delegate() {
        use tokio::io::AsyncReadExt;
        let (client, server) = tokio::io::duplex(64);
        let mut io = ReplayIo::new(b"AB".to_vec(), Box::new(client));
        let mut buf = [0u8; 4];
        let mut done = 0usize;
        while done < 2 {
            let n = io.read(&mut buf).await.unwrap();
            assert!(n > 0);
            done += n;
        }
        assert_eq!(&buf[..2], b"AB");
        // 再读进入透传面（对端无数据则 Pending/阻塞——此处只验回放面收口）
        assert_eq!(io.pos, io.replay.len());
        drop(server);
    }
}
