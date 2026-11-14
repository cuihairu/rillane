//! P3-5 performance-io.md §5：mesh 帧写两段 vs vectored 对照基准（明文回环 TcpStream）。
//!
//! 两写法均镜像 mesh_transport 的帧格式 `[len: u32 BE][payload]`：
//! - `two_segment`：R2 前行为——`write_all(len_be)` + `write_all(payload)`；
//! - `vectored`：R2 行为——两段 IoSlice 一次 `write_vectored` 提交 + 短写推进
//!   （与 mesh_transport::write_frame 同构；函数私有，此处镜像以测 syscall 模式）。
//!
//! 本地实跑、噪声不判 CI（§5/§7.5）。

use std::sync::OnceLock;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const FRAMES_PER_ITER: usize = 2048;

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("tokio runtime"))
}

/// 建一对回环 TCP；返回 (writer, reader_task 句柄前的 reader)。
/// reader 持续读丢弃，直到 writer 半关后 read_to_end 收敛。
async fn pair() -> std::io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (stream, accepted) = tokio::join!(TcpStream::connect(addr), async {
        Ok::<_, std::io::Error>(listener.accept().await?.0)
    },);
    Ok((stream?, accepted?))
}

async fn run_frames(payload_len: usize, two_segment: bool) -> std::io::Result<()> {
    let (mut w, mut r) = pair().await?;
    let len_be = (payload_len as u32).to_be_bytes();
    let payload = vec![0u8; payload_len];

    let reader = tokio::spawn(async move {
        // 总量 = FRAMES_PER_ITER × (4 + payload)；读满即收敛，不等半关
        let total = FRAMES_PER_ITER * (4 + payload_len);
        let mut got = 0usize;
        let mut buf = vec![0u8; 64 * 1024];
        while got < total {
            let n = r.read(&mut buf).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "reader EOF before total",
                ));
            }
            got += n;
        }
        drop(r);
        Ok::<_, std::io::Error>(got)
    });

    for _ in 0..FRAMES_PER_ITER {
        if two_segment {
            w.write_all(&len_be).await?;
            w.write_all(&payload).await?;
        } else {
            // 镜像 mesh_transport::write_frame：两段 IoSlice + 短写推进
            let parts: [&[u8]; 2] = [&len_be, &payload];
            let (mut si, mut so) = (0usize, 0usize);
            while si < parts.len() {
                let cur = &parts[si][so..];
                let next = parts.get(si + 1).copied().unwrap_or(&[]);
                let bufs = [std::io::IoSlice::new(cur), std::io::IoSlice::new(next)];
                let n = w.write_vectored(&bufs).await?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "0-byte vectored write",
                    ));
                }
                let mut rem = n;
                while rem > 0 && si < parts.len() {
                    let avail = parts[si].len() - so;
                    if rem < avail {
                        so += rem;
                        rem = 0;
                    } else {
                        rem -= avail;
                        si += 1;
                        so = 0;
                    }
                }
            }
        }
    }
    w.shutdown().await?;
    reader.await.expect("reader task")?;
    Ok(())
}

fn bench_write_frame(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_frame");
    for payload_len in [4096usize, 64 * 1024] {
        let total = (FRAMES_PER_ITER * (4 + payload_len)) as u64;
        group.throughput(Throughput::Bytes(total));
        for (name, two_segment) in [("two_segment", true), ("vectored", false)] {
            group.bench_with_input(
                BenchmarkId::new(name, format!("payload_{}", payload_len)),
                &two_segment,
                |b, &two_segment| {
                    b.iter(|| {
                        runtime()
                            .block_on(run_frames(payload_len, two_segment))
                            .expect("write_frame iteration");
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_write_frame);
criterion_main!(benches);
