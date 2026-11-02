//! sing-box api 连接事件流（M12）：用户级计量数据源 + 连接日志（M14）。
//!
//! sing-box 1.14+ 官方自带的 api service 把每条连接的增量（含连接关闭
//! 事件）流式推送，Connection.user 就是入站认证的凭据用户名——短连接零
//! 盲区，官方 release 无需任何编译 tag。protobuf 手工解码（依赖最小化）。

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use anyhow::{bail, Context, Result};
use tokio_tungstenite::tungstenite::Message;

/// 一条连接的生命周期明细（M14 连接日志）：New 建、Update 累加、Closed
/// 定稿推入待推缓冲。
#[derive(Debug, Clone)]
struct ConnLife {
    id: String,
    user: String,
    inbound: String,
    network: String,
    source: String,
    destination: String,
    domain: String,
    first: i64,
    last: i64,
    up: i64,
    down: i64,
}

fn conn_lives() -> &'static Mutex<HashMap<String, ConnLife>> {
    static C: OnceLock<Mutex<HashMap<String, ConnLife>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 待推给 hub 的连接日志行（定稿与活跃快照混合，hub 按 conn id upsert）。
fn pending_conn_logs() -> &'static Mutex<Vec<ConnLife>> {
    static P: OnceLock<Mutex<Vec<ConnLife>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(Vec::new()))
}

/// 把待推行 drain 成 JSON 数组（connection.logs 的 params）。行不可用时返回 None。
pub fn connection_logs_frame() -> Option<Message> {
    let rows = std::mem::take(&mut *pending_conn_logs().lock().unwrap());
    if rows.is_empty() {
        return None;
    }
    let arr: Vec<serde_json::Value> = rows
        .iter()
        .map(|l| {
            serde_json::json!({
                "id": l.id, "user": l.user, "inbound": l.inbound,
                "network": l.network, "source": l.source,
                "destination": l.destination, "domain": l.domain,
                "first": l.first, "last": l.last, "up": l.up, "down": l.down,
            })
        })
        .collect();
    Some(Message::Text(
        serde_json::json!({"jsonrpc": "2.0", "method": "connection.logs", "params": arr}).to_string().into(),
    ))
}

/// 连接 id → 凭据用户名（M12）：NEW 事件建立映射，UPDATE/CLOSED 按 id 查。
fn users_of_conn() -> &'static Mutex<HashMap<String, String>> {
    static U: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    U.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 用户级流量增量（按凭据用户名聚合）：订阅任务写入，stats_frame 每 5s
/// drain 一次推给 hub。
fn api_user_deltas() -> &'static Mutex<HashMap<String, (i64, i64)>> {
    static D: OnceLock<Mutex<HashMap<String, (i64, i64)>>> = OnceLock::new();
    D.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn drain_api_user_deltas() -> HashMap<String, (i64, i64)> {
    std::mem::take(&mut api_user_deltas().lock().unwrap())
}

/// 节点级流量增量（按入站 tag 聚合，M15 起替代 clash_api 差分）：事件流的
/// UPDATE/CLOSED 把增量按所属连接的 inbound 累在这里，stats_frame 每 5s
/// drain 推给 hub 落采样。clash 轮询做差对亚秒级短连接存在系统性盲区
/// （连接在下一次轮询前就消失了），事件流每笔增量必达，无此问题。
fn api_tag_deltas() -> &'static Mutex<HashMap<String, (i64, i64)>> {
    static D: OnceLock<Mutex<HashMap<String, (i64, i64)>>> = OnceLock::new();
    D.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn drain_api_tag_deltas() -> HashMap<String, (i64, i64)> {
    std::mem::take(&mut api_tag_deltas().lock().unwrap())
}

/// 核心（重）启/停止前清空连接态：连接 id 属于 sing-box 进程生命周期，
/// 重启后旧 id 不会再有任何事件，不清理则 conn_lives 泄漏且永不定稿。
/// 已知总量先移交 pending 落库；api_user_deltas 按 user 记账、与连接 id
/// 无关，保留给 ticker 正常 drain。订阅意外断开（核心仍在运行）时**不清**：
/// 存量连接的 id 依旧有效，清了反而停掉它们的计量。
pub(super) fn reset_conn_state() {
    let stale: Vec<ConnLife> = conn_lives().lock().unwrap().drain().map(|(_, l)| l).collect();
    pending_conn_logs().lock().unwrap().extend(stale);
    users_of_conn().lock().unwrap().clear();
}

/// 常驻任务：订阅本机 sing-box api 的连接事件流，把 uplink/downlink 增量
/// 按用户累加。断开（核心重启/升级）后 3s 重连；核心未运行或未配置 api
/// service 时静默等待。
pub async fn api_events_loop() {
    loop {
        let Some(port) = super::singbox::restore_api() else {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        };
        match subscribe_connections(port).await {
            Ok(()) => {}
            Err(e) => eprintln!("[stats] sing-box api 订阅断开: {e:#}"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

/// 订阅连接事件流直到断开。每个事件帧按 user 把 delta 累加进聚合表；
/// NEW 事件（delta 为零）天然被过滤。
async fn subscribe_connections(port: u16) -> Result<()> {
    use h2::client;

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let (mut send_request, connection) = client::handshake(tcp).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("http://127.0.0.1/daemon.StartedService/SubscribeConnections")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .context("gRPC 请求头")?;
    let (response, mut send_body) = send_request.send_request(request, false).context("gRPC 连接")?;
    // SubscribeConnectionsRequest{ interval: 5000 }：field1 int64。
    let mut msg = vec![0x08];
    push_varint(&mut msg, 5000);
    let mut frame = Vec::with_capacity(5 + msg.len());
    frame.push(0);
    frame.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    frame.extend_from_slice(&msg);
    send_body.send_data(frame.into(), true).context("gRPC 请求体")?;
    let response = response.await.context("gRPC 响应")?;
    if !response.status().is_success() {
        bail!("sing-box api 返回 {}", response.status());
    }
    let mut body = response.into_body();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.context("gRPC 数据流")?;
        buf.extend_from_slice(chunk.as_ref());
        let _ = body.flow_control().release_capacity(chunk.len());
        while buf.len() >= 5 {
            let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            if buf.len() < 5 + len {
                break;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            match decode_connection_event(&buf[5..5 + len]) {
                Some(ConnEvent::New { id, user, inbound, network, source, destination, domain }) => {
                    users_of_conn().lock().unwrap().insert(id.clone(), user.clone());
                    conn_lives().lock().unwrap().insert(
                        id.clone(),
                        ConnLife {
                            id,
                            user,
                            inbound,
                            network,
                            source,
                            destination,
                            domain,
                            first: now,
                            last: now,
                            up: 0,
                            down: 0,
                        },
                    );
                }
                Some(ConnEvent::Update { id, up, down }) => {
                    // 配额计量（M12 管道，保持不变）。
                    let user = users_of_conn().lock().unwrap().get(&id).cloned();
                    if let Some(user) = user {
                        let mut d = api_user_deltas().lock().unwrap();
                        let e = d.entry(user).or_insert((0, 0));
                        e.0 += up;
                        e.1 += down;
                    }
                    // 连接日志（M14）：明细累加；节点级（M15）按 inbound 同步入账。
                    if let Some(l) = conn_lives().lock().unwrap().get_mut(&id) {
                        l.up += up;
                        l.down += down;
                        l.last = now;
                        let mut td = api_tag_deltas().lock().unwrap();
                        // 表按 (rx, tx) 存：事件 up=客户端上传→tx，down=下载→rx。
                        let e = td.entry(l.inbound.clone()).or_insert((0, 0));
                        e.0 += down;
                        e.1 += up;
                    }
                }
                Some(ConnEvent::Closed { id, up, down }) => {
                    // 定稿补最后一拍：CLOSED 若带增量（官方核心当前不带）
                    // 先入账，避免关闭前最后一拍丢失。
                    if up > 0 || down > 0 {
                        let user = users_of_conn().lock().unwrap().get(&id).cloned();
                        if let Some(user) = user {
                            let mut d = api_user_deltas().lock().unwrap();
                            let e = d.entry(user).or_insert((0, 0));
                            e.0 += up;
                            e.1 += down;
                        }
                        if let Some(l) = conn_lives().lock().unwrap().get_mut(&id) {
                            l.up += up;
                            l.down += down;
                            l.last = now;
                            let mut td = api_tag_deltas().lock().unwrap();
                            // 表按 (rx, tx) 存：事件 up=客户端上传→tx，down=下载→rx。
                            let e = td.entry(l.inbound.clone()).or_insert((0, 0));
                            e.0 += down;
                            e.1 += up;
                        }
                    }
                    users_of_conn().lock().unwrap().remove(&id);
                    if let Some(l) = conn_lives().lock().unwrap().remove(&id) {
                        pending_conn_logs().lock().unwrap().push(l);
                    }
                }
                None => {}
            }
            buf.drain(..5 + len);
        }
    }
    Ok(())
}

/// 一条连接事件（M12）：NEW 带完整连接（含用户），UPDATE 只带 id 与增量，
/// CLOSED 带 id 与可能的收尾增量——用户归属需要调用方按 id 从 NEW 里记的
/// 映射查回。
#[derive(Debug, PartialEq)]
enum ConnEvent {
    New {
        id: String,
        user: String,
        inbound: String,
        network: String,
        source: String,
        destination: String,
        domain: String,
    },
    Update {
        id: String,
        up: i64,
        down: i64,
    },
    /// 官方核心（1.14 实测）CLOSED 不带增量，up/down 恒零；字段保留以兼容
    /// 带增量的版本——带了就由聚合分支补最后一拍。
    Closed {
        id: String,
        up: i64,
        down: i64,
    },
}

/// 解码一条连接事件帧（实测线上格式：gRPC 帧之内最外层是一个 wire2 信封，
/// 里面才是 type=1 varint、id=2 bytes、connection=3 bytes、uplinkDelta=4、
/// downlinkDelta=5、closedAt=6；connection 里 user=10 bytes）。
fn decode_connection_event(buf: &[u8]) -> Option<ConnEvent> {
    let mut event: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < buf.len() {
        let (key, n) = read_varint(buf, i).ok()?;
        i = n;
        match (key >> 3, key & 7) {
            (1, 2) => {
                let (len, n) = read_varint(buf, i).ok()?;
                i = n;
                let end = (i + len as usize).min(buf.len());
                event = Some(buf[i..end].to_vec());
                i = end;
            }
            _ => {
                let (_, n) = skip_field(buf, i, key & 7).ok()?;
                i = n;
            }
        }
    }
    let buf: &[u8] = &event?;
    let mut kind = 0u64;
    let mut id = String::new();
    let mut connection: Option<Vec<u8>> = None;
    let mut up = 0i64;
    let mut down = 0i64;
    let mut i = 0;
    while i < buf.len() {
        let (key, n) = read_varint(buf, i).ok()?;
        i = n;
        let (num, wire) = (key >> 3, key & 7);
        match (num, wire) {
            (1, 0) => {
                let (v, n) = read_varint(buf, i).ok()?;
                i = n;
                kind = v;
            }
            (2, 2) => {
                let (len, n) = read_varint(buf, i).ok()?;
                i = n;
                let end = (i + len as usize).min(buf.len());
                id = String::from_utf8_lossy(&buf[i..end]).into_owned();
                i = end;
            }
            (3, 2) => {
                let (len, n) = read_varint(buf, i).ok()?;
                i = n;
                let end = (i + len as usize).min(buf.len());
                connection = Some(buf[i..end].to_vec());
                i = end;
            }
            (4, 0) => {
                let (v, n) = read_varint(buf, i).ok()?;
                i = n;
                up = v as i64;
            }
            (5, 0) => {
                let (v, n) = read_varint(buf, i).ok()?;
                i = n;
                down = v as i64;
            }
            _ => {
                let (_, n) = skip_field(buf, i, wire).ok()?;
                i = n;
            }
        }
    }
    // UPDATE 只带 id 与增量（无 connection）；NEW 才携带完整连接。
    if kind == 2 {
        return Some(ConnEvent::Closed { id, up, down });
    }
    if kind == 1 {
        return Some(ConnEvent::Update { id, up, down });
    }
    let connection = connection?;
    let conn: &[u8] = &connection;
    let mut user = String::new();
    let mut inbound = String::new();
    let mut network = String::new();
    let mut source = String::new();
    let mut destination = String::new();
    let mut domain = String::new();
    let mut i = 0;
    while i < conn.len() {
        let (key, n) = read_varint(conn, i).ok()?;
        i = n;
        let (num, wire) = (key >> 3, key & 7);
        if wire == 2 {
            let (len, n) = read_varint(conn, i).ok()?;
            i = n;
            let end = (i + len as usize).min(conn.len());
            let val = String::from_utf8_lossy(&conn[i..end]).into_owned();
            i = end;
            match num {
                2 => inbound = val,
                6 => source = val,
                7 => destination = val,
                8 => domain = val,
                10 => user = val,
                _ => {}
            }
        } else {
            match (num, wire) {
                (5, 0) => {
                    let (v, n) = read_varint(conn, i).ok()?;
                    i = n;
                    // network 枚举：sing-box adapter.Network，1=tcp 2=udp。
                    network = if v == 2 { "udp".into() } else { "tcp".into() };
                }
                _ => {
                    let (_, n) = skip_field(conn, i, wire).ok()?;
                    i = n;
                }
            }
        }
    }
    Some(ConnEvent::New { id, user, inbound, network, source, destination, domain })
}

fn read_varint(buf: &[u8], mut i: usize) -> Result<(u64, usize)> {
    let mut v = 0u64;
    let mut shift = 0;
    loop {
        let b = *buf.get(i).context("protobuf 截断")?;
        i += 1;
        v |= u64::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return Ok((v, i));
        }
        shift += 7;
        if shift > 63 {
            bail!("protobuf varint 过长");
        }
    }
}

/// 跳过一个未知 protobuf 字段，返回 (wire type 0 时的值, 新偏移)。
fn skip_field(buf: &[u8], i: usize, wire: u64) -> Result<(Option<u64>, usize)> {
    match wire {
        0 => {
            let (v, n) = read_varint(buf, i)?;
            Ok((Some(v), n))
        }
        1 => Ok((None, (i + 8).min(buf.len()))),
        2 => {
            // 长度前缀在 i 处，值从 i+1 起：新偏移 = (len 前缀之后) + 值长度。
            let (len, n) = read_varint(buf, i)?;
            Ok((None, n + len as usize))
        }
        5 => Ok((None, (i + 4).min(buf.len()))),
        w => bail!("未知 wire type {w}"),
    }
}

fn push_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::hex;

    /// 手工拼 gRPC 事件帧内的信封：外层 wire2（field2=事件体），事件里
    /// type=1 varint、id=2 bytes、uplinkDelta=4 / downlinkDelta=5 varint。
    fn envelope(event: &[u8]) -> Vec<u8> {
        let mut buf = vec![0x0A, event.len() as u8];
        buf.extend_from_slice(event);
        buf
    }

    /// 架构巡检批次4：与 hub 的 golden_fixture_decodes_identically_across_repos
    /// 共享同一份 src/testdata/singbox-events.golden 与同一个 sha 常量——两仓
    /// 解码器对同一字节必须解出同一事件序列（协议知识单一事实源，夹具改动
    /// 必须两仓同步并同步换常量）。
    #[test]
    fn golden_fixture_decodes_identically_across_repos() {
        const GOLDEN_SHA: &str = "94870bb2c541976ad13a9357bf029bbbcb1d1c0c4dbd48a7f82de3a3f7864791";
        // 注：相对路径以本文件为锚——拆分后 events.rs 在 src/proxy/ 下，
        // golden 夹具仍在 src/testdata/，故回退一级再进。
        let golden = include_bytes!("../testdata/singbox-events.golden");
        use sha2::{Digest, Sha256};
        assert_eq!(
            hex(&Sha256::digest(golden)),
            GOLDEN_SHA,
            "golden 夹具与两仓共享版本不一致：任何一侧改动都要同步另一侧"
        );

        let mut rest = &golden[..];
        let mut events = Vec::new();
        while !rest.is_empty() {
            let n = rest[0] as usize;
            events.push(decode_connection_event(&rest[1..1 + n]).expect("golden 帧必须可解码"));
            rest = &rest[1 + n..];
        }
        assert_eq!(events.len(), 3);
        match &events[0] {
            ConnEvent::New { id, user, inbound, network, source, destination, domain } => {
                assert_eq!(
                    (id.as_str(), user.as_str(), inbound.as_str(), network.as_str()),
                    ("conn-1", "alice", "in-11990", "udp")
                );
                assert_eq!(
                    (source.as_str(), destination.as_str(), domain.as_str()),
                    ("1.2.3.4:5", "example.com:443", "example.com")
                );
            }
            other => panic!("第一帧应为 NEW：{other:?}"),
        }
        assert_eq!(
            events[1],
            ConnEvent::Update { id: "e0a2d363-617b-47be-9aca-bbcd376e53ad".into(), up: 1570, down: 0 }
        );
        assert_eq!(events[2], ConnEvent::Closed { id: "c1".into(), up: 111, down: 222 });
    }

    #[test]
    fn a_closed_event_with_final_deltas_decodes_both() {
        // CLOSED { id: "c1", uplinkDelta: 111, downlinkDelta: 222 }
        let event = [0x08, 0x02, 0x12, 0x02, b'c', b'1', 0x20, 0x6F, 0x28, 0xDE, 0x01];
        assert_eq!(
            decode_connection_event(&envelope(&event)),
            Some(ConnEvent::Closed { id: "c1".into(), up: 111, down: 222 })
        );
    }

    #[test]
    fn an_update_event_decodes_id_and_deltas() {
        // UPDATE { id: "u9", uplinkDelta: 1, downlinkDelta: 2 }
        let event = [0x08, 0x01, 0x12, 0x02, b'u', b'9', 0x20, 0x01, 0x28, 0x02];
        assert_eq!(
            decode_connection_event(&envelope(&event)),
            Some(ConnEvent::Update { id: "u9".into(), up: 1, down: 2 })
        );
    }
}
