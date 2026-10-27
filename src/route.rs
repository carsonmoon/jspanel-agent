//! 回程线路探测（四期）：ICMP traceroute。
//!
//! raw ICMP socket（IPPROTO_ICMP）实现：内核代填 IP 头，我们逐 TTL 发 ICMP
//! Echo，接收侧按 id+seq 认领应答——Type 11（Time Exceeded）是中间跳（外层
//! 源地址即该跳路由器），Type 0（Echo Reply）是到达目标，Type 3 是目标不可
//! 达（链路终点，非回程信息）。需要 root（CAP_NET_RAW）；monitor-agent 以
//! root 运行。
//!
//! 全程阻塞式（最坏 25 跳 × 800ms ≈ 20s），在 `spawn_blocking` 里跑，不堵
//! 单线程 runtime 的心跳与上报。

use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

use serde_json::{json, Value};

const MAX_HOPS: u8 = 25;
const HOP_TIMEOUT_MS: u64 = 800;
const PAYLOAD: &[u8] = b"route-probe";

struct RawIcmp {
    fd: i32,
}

impl RawIcmp {
    fn new() -> io::Result<Self> {
        // SOCK_CLOEXEC：musl 的 libc 绑定未导出该常量，用它的 Linux 数值。
        const SOCK_CLOEXEC: i32 = 0o2000000;
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW | SOCK_CLOEXEC, libc::IPPROTO_ICMP) };
        if fd < 0 {
            let e = io::Error::last_os_error();
            return Err(if e.raw_os_error() == Some(libc::EPERM) {
                io::Error::new(e.kind(), "raw socket 需要 root（CAP_NET_RAW）")
            } else {
                e
            });
        }
        Ok(Self { fd })
    }

    fn set_ttl(&self, ttl: u8) -> io::Result<()> {
        let ttl: i32 = ttl.into();
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::IPPROTO_IP,
                libc::IP_TTL,
                &ttl as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    // libc 在 musl target 上把 time_t/suseconds_t 标了 deprecated（musl 1.2
    // 位宽变更预告，rust-libc #1848）。构建目标恒为 64 位（x86_64/aarch64），
    // 两别名现在与将来都是 64 位，显式 `as` 转换语义不变——知情使用。
    #[allow(deprecated)]
    fn set_recv_timeout(&self, d: Duration) -> io::Result<()> {
        let tv = libc::timeval {
            tv_sec: d.as_secs() as libc::time_t,
            tv_usec: d.subsec_micros() as libc::suseconds_t,
        };
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn send_to(&self, packet: &[u8], target: Ipv4Addr) -> io::Result<()> {
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
            sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(target.octets()) },
            sin_zero: [0; 8],
        };
        let rc = unsafe {
            libc::sendto(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// 收一个 ICMP 包，返回 (源 IP, 整个收到的帧，含 IP 头)。超时返回 None。
    fn recv(&self, timeout: Duration) -> io::Result<Option<(Ipv4Addr, Vec<u8>)>> {
        self.set_recv_timeout(timeout)?;
        let mut buf = [0u8; 1500];
        let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut addrlen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut addr as *mut libc::sockaddr_storage as *mut libc::sockaddr,
                &mut addrlen,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::EAGAIN) => Ok(None),
                Some(libc::EINTR) => Ok(None),
                _ => Err(e),
            };
        }
        let src = unsafe { (*(&addr as *const libc::sockaddr_storage as *const libc::sockaddr_in)).sin_addr };
        let src = Ipv4Addr::from(u32::from_be(src.s_addr));
        Ok(Some((src, buf[..n as usize].to_vec())))
    }
}

impl Drop for RawIcmp {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// ICMP 校验和：16 位字反码求和再取反码。
fn checksum(packet: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in packet.chunks(2) {
        let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// 组一个 ICMP Echo：type 8 code 0，id/seq 由调用方给（用于应答认领）。
fn echo_packet(id: u16, seq: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + PAYLOAD.len());
    p.push(8);
    p.push(0);
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(PAYLOAD);
    let sum = checksum(&p);
    p[2..4].copy_from_slice(&sum.to_be_bytes());
    p
}

/// 一帧应答的归属与含义。
enum Answer {
    /// Echo Reply：目标应答，链路到底。
    Reached,
    /// Time Exceeded：中间路由器的地址。
    FromHop,
    /// 不可达（type 3）：链路在该跳终止（防火墙拒绝或目标端口关闭）。
    /// 源地址仍记录为最后一跳。
    DeadEnd,
    /// 不是我们的探测（id 不匹配）。
    Foreign,
}

/// 从收到的帧里认领我们的探测：
/// - Echo Reply（type 0）：外层 ICMP 的 id 即我们的 id；
/// - Time Exceeded（type 11）/ 不可达（type 3）：外层 ICMP 的 8 字节头之后
///   内嵌原始数据报（IP 头 + 原始 Echo 头），id 在原始 Echo 的第 5-6 字节。
fn classify(frame: &[u8], id: u16) -> Option<Answer> {
    let ihl = (*frame.first()? & 0x0F) as usize * 4;
    if frame.len() < ihl + 8 {
        return None;
    }
    let icmp = &frame[ihl..];
    match icmp[0] {
        0 => (icmp[4..6] == id.to_be_bytes()).then_some(Answer::Reached),
        11 | 3 => {
            let inner_ip = icmp.get(8..)?;
            let inner_ihl = (inner_ip.first()? & 0x0F) as usize * 4;
            let echo = inner_ip.get(inner_ihl..)?;
            if echo.get(4..6)? != id.to_be_bytes() {
                return Some(Answer::Foreign);
            }
            Some(if icmp[0] == 11 { Answer::FromHop } else { Answer::DeadEnd })
        }
        _ => None,
    }
}

/// 单次 traceroute：逐 TTL 发 Echo、读应答。返回每跳地址（None=该跳超时）
/// 与是否到达目标。
pub fn trace(target: Ipv4Addr, id: u16) -> io::Result<(Vec<Option<Ipv4Addr>>, bool)> {
    let sender = RawIcmp::new()?;
    let receiver = RawIcmp::new()?;
    receiver.set_recv_timeout(Duration::from_millis(HOP_TIMEOUT_MS))?;
    let mut hops: Vec<Option<Ipv4Addr>> = Vec::new();
    let mut done = false;
    for ttl in 1..=MAX_HOPS {
        sender.set_ttl(ttl)?;
        let seq = u16::from(ttl);
        sender.send_to(&echo_packet(id, seq), target)?;
        // 只认领本探针的应答：其他 TTL/其它 id 的 ICMP 静默丢弃，直到超时。
        let mut addr = None;
        while let Some((src, frame)) = receiver.recv(Duration::from_millis(HOP_TIMEOUT_MS))? {
            match classify(&frame, id) {
                Some(Answer::Reached) => {
                    addr = Some(src);
                    done = true;
                    break;
                }
                Some(Answer::DeadEnd) => {
                    addr = Some(src);
                    done = true;
                    break;
                }
                Some(Answer::FromHop) => {
                    addr = Some(src);
                    break;
                }
                Some(Answer::Foreign) | None => continue,
            }
        }
        hops.push(addr);
        if done {
            break;
        }
    }
    Ok((hops, done))
}

/// `route.probe` RPC 入口：params {target}，返回 {hops: [{ttl, ip}], done}。
/// 阻塞探测放 spawn_blocking。
pub async fn probe(params: Value) -> Result<Value, anyhow::Error> {
    let target = params["target"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("缺少 target"))?
        .parse::<Ipv4Addr>()
        .map_err(|e| anyhow::anyhow!("target 要是 IPv4 地址：{e}"))?;
    let id: u16 = rand::random();
    let (hops, done) = tokio::task::spawn_blocking(move || trace(target, id))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))??;
    let hops: Vec<Value> = hops
        .into_iter()
        .enumerate()
        .map(|(i, addr)| {
            json!({
                "ttl": i + 1,
                "ip": addr.map(|a| a.to_string()),
            })
        })
        .collect();
    Ok(json!({ "hops": hops, "done": done }))
}

/// 与 proxy::dispatch 同形的入口：hub 的 call_agent 请求进来，结果按 id 回。
pub fn dispatch(
    method: String,
    params: Value,
    id: Option<String>,
    result_tx: &tokio::sync::mpsc::Sender<tokio_tungstenite::tungstenite::Message>,
) {
    let Some(id) = id else { return };
    let tx = result_tx.clone();
    tokio::spawn(async move {
        let outcome = probe(params).await;
        let frame = match outcome {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(e) => {
                eprintln!("[route] {method} failed: {e:#}");
                json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": {"code": "ROUTE_ERROR", "message": format!("{e:#}")},
                })
            }
        };
        let _ = tx.send(tokio_tungstenite::tungstenite::Message::Text(frame.to_string().into())).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_packets_carry_a_valid_checksum_and_their_identity() {
        let p = echo_packet(0xBEEF, 7);
        assert_eq!(p[0], 8, "echo request");
        assert_eq!(&p[4..6], &0xBEEFu16.to_be_bytes());
        // 校验和自检：整个包（含校验和字段）再求和应为 0。
        let mut sum = 0u32;
        for pair in p.chunks(2) {
            sum += u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xFFFF, "ones-complement checksum verifies");
    }

    #[test]
    fn time_exceeded_frames_are_claimed_by_the_inner_echo_id() {
        // 外层 IP(20) + Type11 ICMP(8) + 内层 IP(20) + 原始 Echo 头(8)。
        let id: u16 = 0x1234;
        let mut frame = vec![0u8; 56];
        frame[0] = 0x45; // 外层 IP 头（20 字节）
        frame[20] = 11; // 外层 ICMP：Time Exceeded（8 字节头）
        frame[28] = 0x45; // 内层 IP 头（20 字节，28 起）
        frame[52..54].copy_from_slice(&id.to_be_bytes()); // 原始 Echo 的 id（28+20+4）
        assert!(matches!(classify(&frame, id), Some(Answer::FromHop)), "中间跳");
        assert!(matches!(classify(&frame, 0x5678), Some(Answer::Foreign)), "别人的探测不认领");
        // Echo Reply：外层 ICMP 的 id。
        let mut reply = vec![0u8; 28];
        reply[0] = 0x45;
        reply[20] = 0;
        reply[24..26].copy_from_slice(&id.to_be_bytes());
        assert!(matches!(classify(&reply, id), Some(Answer::Reached)), "到达目标");
    }
}
