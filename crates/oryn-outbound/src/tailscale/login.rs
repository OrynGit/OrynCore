//! 注册、交互登录、node key 过期换新与登出（OrynCore#42）。
//! 方案见 Oryn_dev/docs/oryncore/plans/plan-tailscale-login.md；流程对照 tailscale
//! control/controlclient/direct.go `doLogin`：
//! - 返回 AuthURL 时用同一把 node key、以 `Followup` 长轮询，直到用户在浏览器完成登录；
//! - `NodeKeyExpired` 或本机 key 到期时换新 key，旧 key 放进 `OldNodeKey`；
//! - 登出用当前 key 注册，`Expiry` 设为很早的时间。
//!
//! 官方客户端没有到期前的静默续期，这里也不做；到期前 7 天在状态里标记 `expiring_soon`。
use super::control::{self, Control};
use async_trait::async_trait;
use oryn_config::TailscaleSpec;
use serde_json::{json, Value};
use std::{io, time::Duration};
use ts_keys::{NodeKeyPair, NodeState};

/// 单次 `Followup` 长轮询的等待上限，到时用同一 URL 重发（服务端一直挂起请求直到用户登录）。
pub const FOLLOWUP_WAIT: Duration = Duration::from_secs(300);
/// 同一 AuthURL 被立即返回时的退避上限（与官方 authRoutine 一致）。
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// 到期前多久标记 `expiring_soon`。
pub const EXPIRING_SOON_SECS: i64 = 7 * 24 * 3600;
/// 登出时的 `Expiry`：官方用 `time.Unix(123, 0)`。
const LOGOUT_EXPIRY: &str = "1970-01-01T00:02:03Z";

/// 发送一次 RegisterRequest。控制连接实现它；测试用脚本化的假控制面。
#[async_trait]
pub trait Registrar: Send {
    async fn register(&mut self, body: Value) -> io::Result<Value>;
}
#[async_trait]
impl Registrar for Control {
    async fn register(&mut self, body: Value) -> io::Result<Value> {
        Control::register(self, body).await
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Phase {
    /// 尚未启动（没有流量、没有登录请求）。
    #[default]
    Idle,
    /// 正在连接控制面与注册。
    Starting,
    /// 等待用户在浏览器完成登录。
    NeedsLogin,
    Running,
    /// 注册被控制面拒绝（错误见 `error`）。
    Failed,
    /// 已登出：不自动重新注册，直到 `tailscale_login`。
    LoggedOut,
}
impl Phase {
    pub fn name(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Starting => "starting",
            Self::NeedsLogin => "needs-login",
            Self::Running => "running",
            Self::Failed => "failed",
            Self::LoggedOut => "logged-out",
        }
    }
}

#[derive(Debug, Default)]
pub struct LoginState {
    pub phase: Phase,
    /// 只在 `NeedsLogin` 时有值；不写入日志。
    pub auth_url: Option<String>,
    /// 控制面返回的账号显示名，只在内存里。
    pub user: Option<String>,
    pub error: Option<String>,
    /// 待处理的强制重新认证（换新 key、不带 auth key，走浏览器登录）。
    pub force: bool,
    /// 待处理的登出。
    pub logout: bool,
    /// 本机 node key 已到期，下次注册换新 key。
    pub rotate: bool,
}

/// 注册成功。`rotated` 为换下来的旧 node 公钥（需要写回身份文件）。
#[derive(Debug, PartialEq, Eq)]
pub struct Registered {
    pub rotated: Option<String>,
    pub user: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum Answer {
    Done { user: Option<String> },
    Expired,
    Url(String),
}

fn answer(value: &Value) -> io::Result<Answer> {
    if let Some(error) = value["Error"].as_str().filter(|e| !e.is_empty()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Tailscale registration failed: {error}"),
        ));
    }
    if value["NodeKeyExpired"].as_bool() == Some(true) {
        return Ok(Answer::Expired);
    }
    if let Some(url) = value["AuthURL"].as_str().filter(|u| !u.is_empty()) {
        if url.len() > 2048 || !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Tailscale control returned an invalid login URL",
            ));
        }
        return Ok(Answer::Url(url.to_string()));
    }
    let user = value["Login"]["DisplayName"]
        .as_str()
        .or_else(|| value["User"]["DisplayName"].as_str())
        .filter(|n| !n.is_empty() && n.len() <= 256)
        .map(str::to_string);
    Ok(Answer::Done { user })
}

/// RegisterRequest。`auth` 为假时不带 auth key（强制交互登录、登出）。
pub fn request(
    spec: &TailscaleSpec,
    keys: &NodeState,
    old: Option<&str>,
    followup: Option<&str>,
    auth: bool,
    logout: bool,
) -> Value {
    let mut body = json!({
        "Version": u16::from(control::CAP),
        "NodeKey": keys.node_keys.public.to_string(),
        "Hostinfo": control::hostinfo(spec, None),
        "Ephemeral": spec.ephemeral,
    });
    if let Some(old) = old {
        body["OldNodeKey"] = old.into();
    }
    if let Some(url) = followup {
        body["Followup"] = url.into();
    }
    if auth {
        if let Some(key) = &spec.auth_key {
            body["Auth"] = json!({ "AuthKey": key });
        }
    }
    if logout {
        body["Expiry"] = LOGOUT_EXPIRY.into();
    }
    body
}

/// 注册到成功为止。`rotate` 时先换新 node key（本机 key 到期、强制重新认证）；`auth` 为假时
/// 不带 auth key。需要浏览器登录时调用 `needs_login(url)`，然后以 `Followup` 长轮询。
pub async fn register(
    ctl: &mut dyn Registrar,
    spec: &TailscaleSpec,
    keys: &mut NodeState,
    rotate: bool,
    auth: bool,
    needs_login: &(dyn Fn(String) + Send + Sync),
) -> io::Result<Registered> {
    let mut old = None;
    if rotate {
        old = Some(keys.node_keys.public.to_string());
        keys.node_keys = NodeKeyPair::random();
    }
    let mut regenerated = rotate;
    let mut followup: Option<String> = None;
    let mut backoff = Duration::from_secs(1);
    loop {
        let body = request(spec, keys, old.as_deref(), followup.as_deref(), auth, false);
        let value = match &followup {
            None => control::timed(ctl.register(body)).await?,
            // 长轮询：服务端挂起请求直到用户完成登录，单次最多等 FOLLOWUP_WAIT 后用同一 URL 重发
            Some(_) => match tokio::time::timeout(FOLLOWUP_WAIT, ctl.register(body)).await {
                Ok(value) => value?,
                Err(_) => continue,
            },
        };
        match answer(&value)? {
            Answer::Done { user } => return Ok(Registered { rotated: old, user }),
            Answer::Expired => {
                if regenerated {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Tailscale control reports the new node key as expired",
                    ));
                }
                old = Some(keys.node_keys.public.to_string());
                keys.node_keys = NodeKeyPair::random();
                regenerated = true;
                followup = None;
            }
            Answer::Url(url) => {
                if followup.as_deref() == Some(url.as_str()) {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                } else {
                    backoff = Duration::from_secs(1);
                    needs_login(url.clone());
                }
                followup = Some(url);
            }
        }
    }
}

/// 向控制面登出当前 node key。
pub async fn logout(ctl: &mut dyn Registrar, spec: &TailscaleSpec, keys: &NodeState) -> io::Result<()> {
    let value = control::timed(ctl.register(request(spec, keys, None, None, false, true))).await?;
    match answer(&value)? {
        // 登出后控制面可能返回新的登录 URL；本地状态照样清除
        Answer::Done { .. } | Answer::Url(_) | Answer::Expired => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn spec(auth: Option<&str>) -> TailscaleSpec {
        let config = oryn_config::parse_config(&format!(
            "proxies: [{{name: T, type: tailscale{}}}]",
            auth.map(|k| format!(", auth-key: {k}")).unwrap_or_default()
        ))
        .unwrap();
        let oryn_config::OutboundKind::Tailscale(spec) = config.outbounds[0].kind.clone() else {
            panic!()
        };
        spec
    }
    /// 按顺序返回预设应答，并记录收到的请求。`None` 表示挂起（模拟长轮询未完成）。
    struct Script {
        answers: std::collections::VecDeque<Option<Value>>,
        seen: Vec<Value>,
    }
    #[async_trait]
    impl Registrar for Script {
        async fn register(&mut self, body: Value) -> io::Result<Value> {
            self.seen.push(body);
            match self.answers.pop_front() {
                Some(Some(v)) => Ok(v),
                Some(None) => std::future::pending().await,
                None => Err(io::Error::other("script exhausted")),
            }
        }
    }
    fn script(answers: Vec<Option<Value>>) -> Script {
        Script { answers: answers.into(), seen: Vec::new() }
    }
    fn urls() -> (std::sync::Arc<std::sync::Mutex<Vec<String>>>, impl Fn(String) + Send + Sync) {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        (seen, move |url: String| sink.lock().unwrap().push(url))
    }
    #[tokio::test]
    async fn auth_key_registers_directly() {
        let spec = spec(Some("tskey-auth-fixture"));
        let mut keys = NodeState::generate();
        let before = keys.node_keys.public;
        let mut ctl = script(vec![Some(json!({"MachineAuthorized":true}))]);
        let (seen, sink) = urls();
        let r = register(&mut ctl, &spec, &mut keys, false, true, &sink).await.unwrap();
        assert_eq!(r, Registered { rotated: None, user: None });
        assert_eq!(keys.node_keys.public, before);
        assert!(seen.lock().unwrap().is_empty());
        assert_eq!(ctl.seen[0]["Auth"]["AuthKey"], "tskey-auth-fixture");
    }
    /// 失效的 auth key 转为浏览器登录；Followup 长轮询沿用同一把 key，挂起超时后用同一 URL 重发。
    #[tokio::test(start_paused = true)]
    async fn interactive_login_long_polls_followup() {
        let spec = spec(Some("tskey-auth-used"));
        let mut keys = NodeState::generate();
        let url = "https://login.example/a/abc";
        let mut ctl = script(vec![
            Some(json!({"AuthURL": url})),
            None, // 用户还没登录：服务端挂起，到 FOLLOWUP_WAIT 后重发
            Some(json!({"Login":{"DisplayName":"Alice"}})),
        ]);
        let (seen, sink) = urls();
        let r = register(&mut ctl, &spec, &mut keys, false, true, &sink).await.unwrap();
        assert_eq!(r.user.as_deref(), Some("Alice"));
        assert_eq!(*seen.lock().unwrap(), vec![url.to_string()], "URL published once");
        assert_eq!(ctl.seen.len(), 3);
        assert!(ctl.seen[0].get("Followup").is_none());
        for req in &ctl.seen[1..] {
            assert_eq!(req["Followup"], url);
            assert_eq!(req["NodeKey"], ctl.seen[0]["NodeKey"], "same key while waiting");
        }
    }
    /// 控制面报 node key 过期：换新 key 并带 OldNodeKey；新 key 再被报过期则失败，不无限循环。
    #[tokio::test]
    async fn expired_key_rotates_once_with_old_node_key() {
        let spec = spec(Some("tskey-auth-fixture"));
        let mut keys = NodeState::generate();
        let first = keys.node_keys.public.to_string();
        let mut ctl = script(vec![Some(json!({"NodeKeyExpired":true})), Some(json!({}))]);
        let (_, sink) = urls();
        let r = register(&mut ctl, &spec, &mut keys, false, true, &sink).await.unwrap();
        assert_eq!(r.rotated.as_deref(), Some(first.as_str()));
        assert_ne!(keys.node_keys.public.to_string(), first);
        assert_eq!(ctl.seen[1]["OldNodeKey"], first);
        assert_eq!(ctl.seen[1]["Auth"]["AuthKey"], "tskey-auth-fixture");
        let mut ctl = script(vec![Some(json!({"NodeKeyExpired":true})), Some(json!({"NodeKeyExpired":true}))]);
        assert!(register(&mut ctl, &spec, &mut keys, false, true, &sink).await.is_err());
        // 本机已知过期（或强制重新认证）时首个请求就换 key
        let mut keys = NodeState::generate();
        let old = keys.node_keys.public.to_string();
        let mut ctl = script(vec![Some(json!({}))]);
        let r = register(&mut ctl, &spec, &mut keys, true, false, &sink).await.unwrap();
        assert_eq!(r.rotated.as_deref(), Some(old.as_str()));
        assert_eq!(ctl.seen[0]["OldNodeKey"], old);
        assert!(ctl.seen[0].get("Auth").is_none(), "forced re-auth goes through the browser");
    }
    /// 同一 URL 被立即返回时退避，上限 30 s。
    #[tokio::test(start_paused = true)]
    async fn repeated_url_backs_off() {
        let spec = spec(None);
        let mut keys = NodeState::generate();
        let url = json!({"AuthURL":"https://login.example/a/x"});
        let mut answers = vec![Some(url.clone()); 8];
        answers.push(Some(json!({})));
        let mut ctl = script(answers);
        let (seen, sink) = urls();
        let start = tokio::time::Instant::now();
        register(&mut ctl, &spec, &mut keys, false, true, &sink).await.unwrap();
        // 7 次重复：1+2+4+8+16+30+30 = 91 s
        assert_eq!(start.elapsed().as_secs(), 91);
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(ctl.seen[0].get("Auth").is_none(), "no auth key configured");
    }
    #[tokio::test]
    async fn registration_error_is_permission_denied() {
        let spec = spec(None);
        let mut keys = NodeState::generate();
        let mut ctl = script(vec![Some(json!({"Error":"invalid key"}))]);
        let (_, sink) = urls();
        let e = register(&mut ctl, &spec, &mut keys, false, true, &sink).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        let mut ctl = script(vec![Some(json!({"AuthURL":"https://login.example/next"}))]);
        logout(&mut ctl, &spec, &keys).await.unwrap();
        assert_eq!(ctl.seen[0]["Expiry"], LOGOUT_EXPIRY);
    }
    #[test]
    fn answers_follow_do_login_order() {
        assert!(answer(&json!({"Error":"denied","AuthURL":"https://x"})).is_err());
        assert_eq!(answer(&json!({"NodeKeyExpired":true,"AuthURL":"https://x"})).unwrap(), Answer::Expired);
        assert_eq!(
            answer(&json!({"AuthURL":"https://login.example/a/1"})).unwrap(),
            Answer::Url("https://login.example/a/1".into())
        );
        assert!(answer(&json!({"AuthURL":"javascript:alert(1)"})).is_err());
        assert_eq!(
            answer(&json!({"MachineAuthorized":false,"Login":{"DisplayName":"Alice"}})).unwrap(),
            Answer::Done { user: Some("Alice".into()) },
            "MachineAuthorized is only informational"
        );
    }
    #[test]
    fn request_fields() {
        let keys = NodeState::generate();
        let with_key = spec(Some("tskey-auth-fixture"));
        let r = request(&with_key, &keys, None, None, true, false);
        assert_eq!(r["Auth"]["AuthKey"], "tskey-auth-fixture");
        assert!(r.get("OldNodeKey").is_none() && r.get("Followup").is_none() && r.get("Expiry").is_none());
        let r = request(&with_key, &keys, Some("nodekey:old"), Some("https://login.example/a"), false, false);
        assert!(r.get("Auth").is_none(), "forced interactive login omits the auth key");
        assert_eq!(r["OldNodeKey"], "nodekey:old");
        assert_eq!(r["Followup"], "https://login.example/a");
        let r = request(&with_key, &keys, None, None, false, true);
        assert_eq!(r["Expiry"], LOGOUT_EXPIRY);
        assert_eq!(r["NodeKey"], keys.node_keys.public.to_string());
    }
}
