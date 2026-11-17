// 仅编入 engine::utun_tests。非特权 FD 夹具，不是实际 utun 内核或网络线速。
// RawTcp 同样的最小序号状态机，输入改用带 AF 头的 socketpair；不调用 Engine::input。
#[test]
#[ignore = "manual dev FD -> Engine/lwIP/DIRECT loopback payload and control measurement"]
fn utun_direct_continuous_measurement() {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // A/B 用同一 binary、独立串行进程；只在启动前设环境，不在测试中 set_var。
    let seconds: u64 = std::env::var("ORYN_TEST_UTUN_SECONDS")
        .map(|s| s.parse().expect("invalid measurement duration"))
        .unwrap_or(4);
    assert!((1..=4).contains(&seconds));
    let bursts = std::env::var("ORYN_TEST_UTUN_BURSTS").unwrap_or_else(|_| "64/32".into());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dst = listener.local_addr().unwrap();
    let echo = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.set_nodelay(true).unwrap();
        let mut bytes = [0; 16384];
        let mut total = 0usize;
        loop {
            let n = stream.read(&mut bytes).unwrap();
            if n == 0 {
                break;
            }
            stream.write_all(&bytes[..n]).unwrap();
            total += n;
        }
        total
    });
    let (local, peer) = UnixDatagram::pair().unwrap();
    // 与 utun_runtime_tests::pair 一致，避免 Darwin 默认小 datagram 缓冲限制 flight。
    for socket in [&local, &peer] {
        for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
            let size: libc::c_int = 256 * 1024;
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::SOL_SOCKET,
                        option,
                        (&size as *const libc::c_int).cast(),
                        std::mem::size_of_val(&size) as libc::socklen_t,
                    )
                },
                0
            );
        }
    }
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let config = b"geo-auto-update: false\ngeox-url: {asn: ''}\ndns:\n  public-ip-url: ''\nrules: ['MATCH,DIRECT']\n";
    let mut engine = Engine::new(
        config,
        br#"{"local_proxy":{"enabled":false},"resource_profile":"desktop_high"}"#,
    )
    .unwrap();
    engine.set_output(Box::new(|_| panic!("FD backend must not use callback")));
    engine.start_utun(local.as_raw_fd()).unwrap();
    let src = "198.18.0.10:47901".parse().unwrap();
    let send = |seq, ack, flags, payload: &[u8]| {
        let packet = build_tcp(src, dst, seq, ack, flags, 65535, payload).unwrap();
        let mut frame = Vec::with_capacity(1504);
        encode_frame(IpVersion::V4, &packet, &mut frame).unwrap();
        assert_eq!(peer.send(&frame).unwrap(), frame.len());
    };
    let recv = || {
        let mut frame = [0; 65540];
        let n = peer.recv(&mut frame).unwrap();
        let (family, ip) = decode_frame(&frame[..n]).unwrap();
        assert_eq!(family, IpVersion::V4);
        let seg = parse_tcp(ip).unwrap();
        assert_eq!((seg.src, seg.dst), (dst, src));
        assert_eq!(seg.flags & 4, 0, "unexpected RST");
        seg
    };
    send(1000, 0, 2, &[]);
    let synack = recv();
    assert_eq!(synack.flags & 0x12, 0x12);
    assert_eq!(synack.ack, 1001);
    let mut seq = 1001u32;
    let mut ack = synack.seq.wrapping_add(1);
    send(seq, ack, 16, &[]);

    let handle = engine.handle().unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let stop = done.clone();
    let sampler = std::thread::spawn(move || {
        let mut samples = Vec::with_capacity(1024);
        while !stop.load(Ordering::Relaxed) && samples.len() < 1024 {
            let start = Instant::now();
            let stats = handle.command(json!({"cmd":"stats"}));
            assert!(stats.get("error").is_none(), "{stats}");
            samples.push(start.elapsed().as_micros());
            std::thread::sleep(Duration::from_millis(5));
        }
        samples
    });
    // 每轮 flight 仅 8 个 MSS，不需重传或无界队列；任何重复/缺序包直接失败。
    // 这刻意测量含夹具成本的持续 echo goodput，不是 TCP 最大窗口吞吐。
    let pattern = |offset: usize| ((offset.wrapping_mul(31) ^ (offset >> 8)) & 255) as u8;
    let cpu = || {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        assert_eq!(
            unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
            0
        );
        let u = unsafe { usage.assume_init() };
        (u.ru_utime.tv_sec + u.ru_stime.tv_sec) as f64
            + (u.ru_utime.tv_usec + u.ru_stime.tv_usec) as f64 / 1e6
    };
    let cpu_start = cpu();
    let start = Instant::now();
    let mut total = 0usize;
    let mut payload = [0u8; 1200];
    let mut rounds = 0usize;
    while start.elapsed() < Duration::from_secs(seconds) {
        let end = total + 8 * payload.len();
        for offset in (total..end).step_by(payload.len()) {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte = pattern(offset + i);
            }
            send(seq, ack, 24, &payload);
            seq = seq.wrapping_add(payload.len() as u32);
        }
        while total < end {
            let seg = recv();
            assert_eq!(seg.flags & 3, 0, "unexpected SYN/FIN");
            if seg.payload.is_empty() {
                continue;
            }
            assert_eq!(
                seg.seq, ack,
                "gap/duplicate/reordering: no silent packet loss"
            );
            assert!(total + seg.payload.len() <= end);
            for (i, byte) in seg.payload.iter().enumerate() {
                assert_eq!(*byte, pattern(total + i));
            }
            total += seg.payload.len();
            ack = ack.wrapping_add(seg.payload.len() as u32);
            send(seq, ack, 16, &[]);
        }
        rounds += 1;
    }
    let elapsed = start.elapsed();
    let cpu_seconds = cpu() - cpu_start;
    done.store(true, Ordering::Relaxed);
    let mut samples = sampler.join().unwrap();
    assert!(samples.len() >= 10);
    samples.sort_unstable();
    // 已逐字节确认 echo 后以 RST 关闭，确保本地服务退出并独立核对上传总量。
    send(seq, ack, 20, &[]);
    engine.stop();
    assert_eq!(echo.join().unwrap(), total);
    assert_eq!(total, rounds * 8 * payload.len());
    let cpu_per_gib = cpu_seconds / (total as f64 / 1073741824.0);
    eprintln!("write/read={bursts} process_cpu_s_per_GiB_per_direction={cpu_per_gib:.3} flight=8x1200 dev socketpair AF->utun runtime->Engine/lwIP/Router/DIRECT->loopback echo: rounds={rounds} verified_bytes_each_direction={total} payload_s={:.6} per_direction_MiB_s={:.3} process_cpu_s={cpu_seconds:.6} stats_n={} stats_p50_us={} stats_max_us={} (includes harness+echo CPU; NOT real utun kernel/network line rate)", elapsed.as_secs_f64(), total as f64 / 1048576.0 / elapsed.as_secs_f64(), samples.len(), samples[samples.len()/2], samples.last().unwrap());
}
