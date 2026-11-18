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
        let slots = Arc::new(Semaphore::new(1));
        let permit = slots.clone().try_acquire_owned().unwrap();
        // limit=32 复现旧「满节点」窗口预算（active = 32 − 0），保持这些用例的预算语义。
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
    let budget = receive_bytes(MIN_RECV_WINDOW);
    let total = (budget / MAX_SEGMENT * 3) as u32;
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
async fn near_budget_reorder_reserves_room_for_gap() {
    let mut peer = Peer::new().await;
    for seq in 1..=60 {
        assert_eq!(peer.data(seq).await.ack, seq + 1);
    }
    // output 已超过零窗口阈值；乱序段最多接纳到 107，仍为缺口 61 留一段。
    for seq in 62..=110 {
        assert_eq!(peer.data(seq).await.ack, 61);
    }
    let ack = peer.data(61).await;
    assert_eq!(ack.ack, 108);
    assert!((ack.ack as usize - 1) * MAX_SEGMENT <= receive_bytes(MIN_RECV_WINDOW) + 64);
    peer.read_range(1, 108).await;
    loop {
        if peer.next_ack().await.window > 0 {
            break;
        }
    }
    for seq in 108..=110 {
        assert_eq!(peer.data(seq).await.ack, seq + 1);
        peer.read_range(seq, seq + 1).await;
    }
}
