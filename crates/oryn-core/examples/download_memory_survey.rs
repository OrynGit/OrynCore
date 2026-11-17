//! Geo/provider HTTP正文保留峰值基线：生成式AsyncRead，不先分配模拟响应体。
//! download_memory_survey <MiB: 1|8|16> <keep|discard|keep-file|file> <length|chunked> [file-path]
//! discard只是最低保留量对照，不是可持久化下载实现。
use oryn_core::alloc::{heap_usage, Counting};
use std::{
    alloc::System,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[global_allocator]
static GLOBAL: Counting<System> = Counting(System);

struct Response {
    head: Vec<u8>,
    pos: usize,
    left: usize,
    tail: &'static [u8],
}
impl AsyncRead for Response {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.head.len() {
            let n = out.remaining().min(self.head.len() - self.pos);
            out.put_slice(&self.head[self.pos..self.pos + n]);
            self.pos += n;
        } else if self.left > 0 {
            let n = self.left.min(out.remaining()).min(8192);
            out.put_slice(&[0x5a; 8192][..n]);
            self.left -= n;
        } else if !self.tail.is_empty() {
            let n = self.tail.len().min(out.remaining());
            out.put_slice(&self.tail[..n]);
            self.tail = &self.tail[n..];
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Response {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
struct Source(std::sync::Mutex<Option<Response>>);
#[async_trait::async_trait]
impl oryn_http::Connector for Source {
    async fn connect(&self, _: &str, _: u16) -> io::Result<oryn_outbound::BoxStream> {
        Ok(Box::new(
            self.0
                .lock()
                .unwrap()
                .take()
                .expect("one generated response"),
        ))
    }
}
// 与Core文件sink相同的16KiB同步写界限，比较两条路径相同的真实文件落盘工作量。
struct Sink(std::fs::File);
impl AsyncWrite for Sink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        use std::io::Write;
        Poll::Ready(self.0.write(&bytes[..bytes.len().min(16384)]))
    }
    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        use std::io::Write;
        Poll::Ready(self.0.flush())
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

#[cfg(target_os = "macos")]
fn footprint() -> u64 {
    let mut info: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V4,
            &mut info as *mut _ as *mut libc::rusage_info_t,
        )
    };
    if rc == 0 {
        info.ri_phys_footprint
    } else {
        0
    }
}
#[cfg(not(target_os = "macos"))]
fn footprint() -> u64 {
    0
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(matches!(args.len(), 4 | 5));
    let mib: usize = args[1].parse().unwrap();
    assert!([1, 8, 16].contains(&mib));
    let discard = match args[2].as_str() {
        "keep" | "keep-file" => false,
        "discard" | "file" => true,
        _ => panic!("invalid mode"),
    };
    let chunked = match args[3].as_str() {
        "length" => false,
        "chunked" => true,
        _ => panic!("invalid framing"),
    };
    let size = mib * 1024 * 1024;
    let head = if chunked {
        format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size:x}\r\n")
    } else {
        format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n")
    };
    let mut input = Response {
        head: head.into_bytes(),
        pos: 0,
        left: size,
        tail: if chunked { b"\r\n0\r\n\r\n" } else { b"" },
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let file_mode = matches!(args[2].as_str(), "keep-file" | "file");
    let mut file = file_mode.then(|| {
        assert_eq!(args.len(), 5, "file mode needs new output path");
        Sink(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&args[4])
                .unwrap(),
        )
    });
    let before = heap_usage().unwrap();
    let fp_before = footprint();
    let begin = Instant::now();
    let (response, n) = if file_mode {
        let source = Source(std::sync::Mutex::new(Some(input)));
        let req = oryn_http::Request {
            method: "GET",
            url: "http://example.invalid/db",
            headers: &[],
            body: &[],
        };
        let opts = oryn_http::Options {
            max_body: 16 * 1024 * 1024,
            ..Default::default()
        };
        if discard {
            rt.block_on(oryn_http::fetch_to_writer(
                &source,
                req,
                &opts,
                file.as_mut().unwrap(),
            ))
            .unwrap()
        } else {
            use std::io::Write;
            let response = rt.block_on(oryn_http::fetch(&source, req, &opts)).unwrap();
            file.as_mut().unwrap().0.write_all(&response.body).unwrap();
            let n = response.body.len();
            (response, n)
        }
    } else {
        rt.block_on(oryn_http::read_response(
            &mut input,
            false,
            16 * 1024 * 1024,
            discard,
        ))
        .unwrap()
    };
    let elapsed = begin.elapsed().as_micros();
    assert_eq!(n, size);
    assert_eq!(response.body.len(), if discard { 0 } else { size });
    let during = heap_usage().unwrap();
    let fp_during = footprint();
    drop(response);
    let after = heap_usage().unwrap();
    let fp_after = footprint();
    if let Some(sink) = file {
        assert_eq!(sink.0.metadata().unwrap().len() as usize, size);
        drop(sink);
        use std::io::Read;
        let mut saved = std::fs::File::open(&args[4]).unwrap();
        let mut chunk = [0; 16384];
        let mut checked = 0;
        loop {
            let n = saved.read(&mut chunk).unwrap();
            if n == 0 {
                break;
            }
            assert!(chunk[..n].iter().all(|b| *b == 0x5a));
            checked += n;
        }
        assert_eq!(checked, size);
        drop(saved);
        std::fs::remove_file(&args[4]).unwrap();
    }
    println!("mib,mode,framing,elapsed_us,live_before,peak_before,live_body,peak_body,live_after,footprint_before,footprint_body,footprint_after");
    println!(
        "{mib},{},{},{elapsed},{},{},{},{},{},{fp_before},{fp_during},{fp_after}",
        args[2], args[3], before.0, before.1, during.0, during.1, after.0
    );
}
