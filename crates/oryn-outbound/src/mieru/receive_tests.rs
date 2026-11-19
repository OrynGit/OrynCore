use super::*;
use std::collections::HashMap;

struct Peer {
    input: mpsc::Sender<Frame>,
    ack: mpsc::Receiver<Frame>,
    app: DuplexStream,
    task: tokio::task::JoinHandle<io::Result<()>>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Peer {
    async fn new() -> Self {
        Self::with_slots(Arc::new(Semaphore::new(1))).await
    }
    async fn with_slots(slots: Arc<Semaphore>) -> Self {
        let (send, ack) = mpsc::channel(32);
        let carrier = Carrier {
            send,
            close_waiters: Arc::new(Semaphore::new(32)),
            sessions: Mutex::new(HashMap::new()),
            stop: CancellationToken::new(),
            packet: true,
            reusable: true,
            chunk: 1024,
        };
        let (input, rx) = mpsc::channel(RECV_WINDOW);
        // 小桥接使慢应用的额外容量可精确核算；直接驱动产品 run。
        let (app, mut bridge) = tokio::io::duplex(64);
        // run 自身持有 1 个名额（应用写半关闭即归还）；limit=32 对应满节点预算
        // （active = 32 − available）。Peer::new 传容量 1：名额被 run 持有，active 恒为 32。
        let permit = slots.clone().try_acquire_owned().unwrap();
        let task = tokio::spawn(async move {
            run(&carrier, 1, vec![], &mut bridge, rx, &slots, 32, permit).await
        });
        let mut peer = Self {
            input,
            ack,
            app,
            task,
        };
        assert_eq!(peer.ack.recv().await.unwrap().kind, 2);
        peer.input.send(Frame::new(3, 1, 0, vec![])).await.unwrap();
        assert_eq!(peer.next_ack().await.ack, 1);
        peer
    }
    async fn next_ack(&mut self) -> Frame {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let frame = self.ack.recv().await.unwrap();
                if frame.kind == 8 {
                    return frame;
                }
            }
        })
        .await
        .unwrap()
    }
    async fn data(&mut self, seq: u32) -> Frame {
        self.input
            .send(Frame::new(7, 1, seq, payload(seq)))
            .await
            .unwrap();
        self.next_ack().await
    }
    async fn read_range(&mut self, start: u32, end: u32) {
        let mut got = vec![0; (end - start) as usize * MAX_SEGMENT];
        tokio::time::timeout(Duration::from_secs(2), self.app.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, (start..end).flat_map(payload).collect::<Vec<_>>());
    }
}
fn payload(seq: u32) -> Vec<u8> {
    let mut data = vec![0; MAX_SEGMENT];
    for word in data.chunks_mut(4) {
        word.copy_from_slice(&seq.to_be_bytes());
    }
    data
}

#[tokio::test]
async fn slow_app_inorder_hard_budget_and_retransmit_recovery() {
    let mut peer = Peer::new().await;
    let budget = receive_capacity();
    let total = (budget / MAX_SEGMENT + 100) as u32;
    let mut accepted = 1;
    let mut rejected = false;
    for seq in 1..=total {
        let ack = peer.data(seq).await;
        assert!(ack.ack >= accepted);
        accepted = ack.ack;
        // 累计确认代表已接纳的载荷：output + 64 字节 bridge 不得突破预算。
        assert!(
            (accepted as usize - 1) * MAX_SEGMENT <= budget + 64,
            "inorder bypassed receive budget: ack={} budget={budget}",
            ack.ack
        );
        if ack.ack <= seq {
            rejected = true;
            assert_eq!(ack.window, 0);
        }
    }
    assert!(rejected);
    peer.read_range(1, accepted).await;
    // 不发送探测帧，应用排空就必须主动恢复窗口。
    loop {
        let ack = peer.next_ack().await;
        assert_eq!(ack.ack, accepted);
        if ack.window > 0 {
            break;
        }
    }
    for seq in accepted..=total {
        assert_eq!(peer.data(seq).await.ack, seq + 1);
        peer.read_range(seq, seq + 1).await;
    }
    assert_eq!(peer.data(total).await.ack, total + 1);
    let mut byte = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(10), peer.app.read(&mut byte))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn reordered_gap_and_duplicates_preserve_cumulative_ack() {
    let mut peer = Peer::new().await;
    for seq in [3, 2, 3] {
        assert_eq!(peer.data(seq).await.ack, 1);
    }
    assert_eq!(peer.data(1).await.ack, 4);
    assert_eq!(peer.data(2).await.ack, 4);
    peer.read_range(1, 4).await;
    assert_eq!(peer.data(4).await.ack, 5);
    peer.read_range(4, 5).await;
}

#[tokio::test]
async fn near_capacity_reorder_reserves_room_for_gap() {
    let mut peer = Peer::new().await;
    // 缺口在 1；乱序段一直缓存到字节上限（扣除乱序预留的一段）。
    let fill = (receive_capacity() - MAX_SEGMENT) / MAX_SEGMENT;
    for seq in 2..=2 + fill as u32 - 1 {
        assert_eq!(peer.data(seq).await.ack, 1);
    }
    // 缓存已到边缘，缺口段（按序，不占预留）仍然收得下：重排缓存整体交付。
    let ack = peer.data(1).await;
    assert_eq!(ack.ack, 2 + fill as u32);
    assert!(
        (ack.ack as usize - 1) * MAX_SEGMENT <= receive_capacity() + 64,
        "drain bypassed receive capacity"
    );
    peer.read_range(1, 2 + fill as u32).await;
    loop {
        if peer.next_ack().await.window > 0 {
            break;
        }
    }
    let ack = peer.data(2 + fill as u32).await;
    assert_eq!(ack.ack, 3 + fill as u32);
    peer.read_range(2 + fill as u32, 3 + fill as u32).await;
}

/// 缓存到达字节上限后，再来的段被丢弃且不产生重复确认，对端只能等超时逐段恢复。
/// 修复后第一个被丢弃的段必须立即补发确认（累计序号 + 当前窗口），把窗口状态告诉对端；
/// 之后 DROP_NACK_MERGE 内的丢弃合并。断言方式：一串被丢弃的段在 200 ms 内恰好产生
/// 两次确认（立即 + 延迟）。没有立即反馈时延迟确认机制对整串丢弃只回一次（500 ms 的
/// 空闲窗口更新在窗口之外）；没有节流时每个丢弃各回一次，会超过两次。
#[tokio::test]
async fn outside_window_drop_is_acked_immediately_and_merged() {
    // 容量 33 = 32 个测试名额 + run 自持的 1 个。
    let slots = Arc::new(Semaphore::new(33));
    let mut peer = Peer::with_slots(slots.clone()).await;
    // 名额全空闲：active = 1，接收窗口份额 1024。先按序交付几段。
    for seq in 1..=4 {
        assert_eq!(peer.data(seq).await.ack, seq + 1);
    }
    peer.read_range(1, 5).await;
    // 占满名额：active = 32，窗口份额收缩到 64 段（RECV_BUDGET / 32），
    // 但缓存容量固定不变。制造缺口：不发 seq 5，乱序段缓存到字节上限。
    let _permits = slots.acquire_many(32).await.unwrap();
    let fill = (receive_capacity() - MAX_SEGMENT) / MAX_SEGMENT;
    for seq in 6..=5 + fill as u32 {
        let ack = peer.data(seq).await;
        assert_eq!(ack.ack, 5);
    }
    // 缓存已满：再来的段被丢弃。
    for seq in 6 + fill as u32..=10 + fill as u32 {
        peer.input
            .send(Frame::new(7, 1, seq, payload(seq)))
            .await
            .unwrap();
    }
    // 200 ms 内恰好两次确认，都是「缺口 5 + 满载时的窗口」。
    let mut acks = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
    loop {
        match tokio::time::timeout_at(deadline, peer.ack.recv()).await {
            Ok(Some(frame)) if frame.kind == 8 => acks.push(frame),
            _ => break,
        }
    }
    assert_eq!(acks.len(), 2, "drop burst acks: {acks:?}");
    let expected_window =
        receive_window(0, fill * MAX_SEGMENT, MIN_RECV_WINDOW);
    for ack in &acks {
        assert_eq!(ack.ack, 5);
        assert_eq!(ack.window, expected_window);
    }
    // 对端重传缺口段后照常恢复：重排缓存整体交付，被丢弃的段由对端重传补上，
    // 累计确认推进到缺口段之后第一段的序号。
    let first_dropped = 6 + fill as u32;
    let ack = peer.data(5).await;
    assert_eq!(ack.ack, first_dropped);
    peer.read_range(5, first_dropped).await;
    for seq in first_dropped..=first_dropped + 4 {
        peer.input
            .send(Frame::new(7, 1, seq, payload(seq)))
            .await
            .unwrap();
    }
    let last = first_dropped + 5;
    loop {
        let ack = peer.next_ack().await;
        if ack.ack >= last {
            break;
        }
    }
    peer.read_range(first_dropped, last).await;
    // 应用排空后窗口重新打开。
    loop {
        if peer.next_ack().await.window > 0 {
            break;
        }
    }
    let ack = peer.data(last).await;
    assert_eq!(ack.ack, last + 1);
    peer.read_range(last, last + 1).await;
}
