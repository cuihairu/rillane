//! P3-5 performance-io.md §5：TCP relay 缓冲对照基准（本地回环）。
//!
//! 拓扑：source --TCP--> relay(copy_bidirectional_with_sizes) --TCP--> sink。
//! source 单向灌 32 MiB，sink read_to_end 计收毕；criterion 按
//! `Throughput::Bytes` 折算 MiB/s。对照组 8K/32K/64K/256K 缓冲。
//! 本地实跑、噪声不判 CI（§5/§7.5）。

use std::sync::OnceLock;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tokio::io::{copy_bidirectional_with_sizes, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PAYLOAD_BYTES: usize = 32 * 1024 * 1024;
const READ_SINK_BUF: usize = 64 * 1024;

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("tokio runtime"))
}

async fn pump_once(relay_buf: usize) -> std::io::Result<()> {
    // 两条独立回环连接：source→relay_in、relay_out→sink
    let in_listener = TcpListener::bind("127.0.0.1:0").await?;
    let out_listener = TcpListener::bind("127.0.0.1:0").await?;
    let in_addr = in_listener.local_addr()?;
    let out_addr = out_listener.local_addr()?;

    let (relay_in, source) = tokio::join!(
        async { Ok::<_, std::io::Error>(in_listener.accept().await?.0) },
        TcpStream::connect(in_addr),
    );
    let (relay_out, sink) = tokio::join!(
        async { Ok::<_, std::io::Error>(out_listener.accept().await?.0) },
        TcpStream::connect(out_addr),
    );
    let (mut relay_in, mut source) = (relay_in?, source?);
    let (mut relay_out, mut sink) = (relay_out?, sink?);

    let chunk = vec![0xA5u8; 64 * 1024];

    let relay = tokio::spawn(async move {
        let _ = copy_bidirectional_with_sizes(&mut relay_in, &mut relay_out, relay_buf, relay_buf)
            .await;
    });
    let sink = tokio::spawn(async move {
        let mut got = 0usize;
        let mut buf = vec![0u8; READ_SINK_BUF];
        while got < PAYLOAD_BYTES {
            let n = sink.read(&mut buf).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "sink EOF before payload complete",
                ));
            }
            got += n;
        }
        // 主动断开另一方向，让 relay 的 copy_bidirectional 收敛
        drop(sink);
        Ok(())
    });
    let source = tokio::spawn(async move {
        let mut sent = 0usize;
        while sent < PAYLOAD_BYTES {
            let take = PAYLOAD_BYTES - sent;
            let n = take.min(chunk.len());
            source.write_all(&chunk[..n]).await?;
            sent += n;
        }
        source.shutdown().await
    });

    let (r, s, src) = tokio::join!(relay, sink, source);
    r.expect("relay task");
    s.expect("sink task")?;
    src.expect("source task")?;
    Ok(())
}

fn bench_relay_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("relay_throughput");
    group.throughput(Throughput::Bytes(PAYLOAD_BYTES as u64));
    for buf in [8192usize, 32768, 65536, 262144] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("buf_{}", buf)),
            &buf,
            |b, &buf| {
                b.iter(|| {
                    runtime()
                        .block_on(pump_once(buf))
                        .expect("relay pump iteration");
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_relay_throughput);
criterion_main!(benches);
