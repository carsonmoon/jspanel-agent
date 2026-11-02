//! 网络探测：HTTP 探测（hub 协议测速）与落地目标 TCP 健康探测（relay.probe）。
//! http_probe 支持经 socks5 出口链拨号（全链真实延迟）。

use std::time::Duration;

/// HTTP 探测（hub 协议测速用）：从本机向 url 发 GET，测到收到响应头的耗时。
/// 与客户端软件测延迟同款语义（目标一般给 gstatic generate_204）——反映的是
/// 本机出口线路的真实访问质量，含 DNS/TCP/TLS 全程。
async fn http_probe(params: &serde_json::Value) -> serde_json::Value {
    let Some(url) = params["url"].as_str().filter(|u| !u.is_empty()) else {
        return serde_json::json!({ "ok": false, "error": "缺少 url" });
    };
    let timeout_ms = params["timeout_ms"].as_u64().unwrap_or(5000).clamp(500, 15_000);
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        // 不跟随重定向：测的是目标本身的可达性与耗时。
        .redirect(reqwest::redirect::Policy::none());
    // 可选 socks5 出口链：带此参数时经 socks5（socks5h=目标域名由代理端解析）
    // 访问目标，测到的是「本机→socks5→目标」的完整链路。认证从 URL userinfo
    // 读取（socks5 RFC 1929 用户名/密码）。
    if let Some(s5) = params["socks5"].as_object() {
        let server = s5["server"].as_str().unwrap_or_default().trim();
        let port = s5["port"].as_u64().unwrap_or(0);
        if server.is_empty() || port == 0 {
            return serde_json::json!({ "ok": false, "error": "socks5 参数不完整" });
        }
        let auth = match (
            s5.get("username").and_then(|v| v.as_str()),
            s5.get("password").and_then(|v| v.as_str()),
        ) {
            (Some(u), Some(p)) if !u.is_empty() => {
                format!("{}:{}@", pct_url(u), pct_url(p))
            }
            _ => String::new(),
        };
        let proxy = match reqwest::Proxy::all(format!("socks5h://{auth}{server}:{port}")) {
            Ok(p) => p,
            Err(e) => return serde_json::json!({ "ok": false, "error": format!("socks5 配置无效: {e}") }),
        };
        builder = builder.proxy(proxy);
    }
    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => return serde_json::json!({ "ok": false, "error": e.to_string() }),
    };
    let started = std::time::Instant::now();
    match client.get(url).send().await {
        Ok(resp) => serde_json::json!({
            "ok": true,
            "status": resp.status().as_u16(),
            "ms": started.elapsed().as_millis() as u64,
        }),
        // 错误链全展开：socks 层的失败原因（如 GeneralServerFailure）藏在
        // source 里，只给 to_string 会丢掉诊断信息。
        Err(e) => {
            let mut parts = vec![e.to_string()];
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                parts.push(s.to_string());
                src = s.source();
            }
            serde_json::json!({ "ok": false, "error": parts.join(" ← ") })
        }
    }
}

/// 落地目标健康探测（hub 发起）：从本机对每个 host:port 做 TCP connect。
/// count=1 时与旧版行为一致（results[].ms = 单次耗时）；count>1 为诊断模式，
/// 连发多次（interval_ms 间隔）并聚合 avg_ms / loss_pct 供诊断弹窗分级。
/// 只测 TCP——xwPF 的 `nc -z` 同款；UDP 服务探不了，由 hub 标 unknown。
async fn relay_probe(params: &serde_json::Value) -> Vec<serde_json::Value> {
    let timeout_ms = params["timeout_ms"].as_u64().unwrap_or(3000).clamp(100, 10_000);
    let count = params["count"].as_u64().unwrap_or(1).clamp(1, 20) as usize;
    let interval_ms = params["interval_ms"].as_u64().unwrap_or(0).min(1000);
    let mut results = Vec::new();
    let Some(targets) = params["targets"].as_array() else { return results };
    for t in targets {
        let Some(addr) = t.as_str() else { continue };
        let mut samples: Vec<Option<u64>> = Vec::with_capacity(count);
        for i in 0..count {
            if i > 0 && interval_ms > 0 {
                tokio::time::sleep(Duration::from_millis(interval_ms)).await;
            }
            let started = std::time::Instant::now();
            let ok = matches!(
                tokio::time::timeout(Duration::from_millis(timeout_ms), tokio::net::TcpStream::connect(addr))
                    .await,
                Ok(Ok(_))
            );
            samples.push(ok.then(|| started.elapsed().as_millis() as u64));
        }
        let (ok, avg_ms, loss_pct) = summarize_probe(&samples);
        results.push(serde_json::json!({
            "target": addr,
            "ok": ok,
            "ms": samples.iter().flatten().next().copied().unwrap_or(0),
            "avg_ms": avg_ms,
            "loss_pct": loss_pct,
        }));
    }
    results
}

/// 一组探测样本（None=超时/失败）的聚合：是否至少通一次、成功样本平均毫秒、
/// 丢包率（百分比，一位小数精度由调用方按需取整）。
fn summarize_probe(samples: &[Option<u64>]) -> (bool, u64, f64) {
    let ok_count = samples.iter().filter(|s| s.is_some()).count();
    let ok = ok_count > 0;
    let avg_ms = if ok_count == 0 { 0 } else { samples.iter().flatten().sum::<u64>() / ok_count as u64 };
    let loss_pct = 100.0 * (samples.len() - ok_count) as f64 / samples.len().max(1) as f64;
    (ok, avg_ms, loss_pct)
}

/// URL userinfo 的百分号编码（socks5 认证串里的用户名/密码可能含特殊字符）。
fn pct_url(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(*b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 极简 socks5 服务（仅 CONNECT，无认证）：http_probe 的 socks5 拨号测试用。
#[cfg(test)]
async fn mini_socks5(listener: tokio::net::TcpListener) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let Ok((mut sock, _)) = listener.accept().await else { return };
        tokio::spawn(async move {
            let mut hdr = [0u8; 2];
            if sock.read_exact(&mut hdr).await.is_err() {
                return;
            }
            let mut methods = vec![0u8; hdr[1] as usize];
            if sock.read_exact(&mut methods).await.is_err() {
                return;
            }
            if sock.write_all(&[5, 0]).await.is_err() {
                return;
            }
            let mut req = [0u8; 4];
            if sock.read_exact(&mut req).await.is_err() {
                return;
            }
            let addr = match req[3] {
                1 => {
                    let mut b = [0u8; 4];
                    if sock.read_exact(&mut b).await.is_err() {
                        return;
                    }
                    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
                }
                3 => {
                    let mut l = [0u8; 1];
                    if sock.read_exact(&mut l).await.is_err() {
                        return;
                    }
                    let mut b = vec![0u8; l[0] as usize];
                    if sock.read_exact(&mut b).await.is_err() {
                        return;
                    }
                    String::from_utf8(b).unwrap_or_default()
                }
                _ => return,
            };
            let mut p = [0u8; 2];
            if sock.read_exact(&mut p).await.is_err() {
                return;
            }
            let port = u16::from_be_bytes(p);
            let Ok(mut upstream) = tokio::net::TcpStream::connect((addr.as_str(), port)).await else {
                let _ = sock.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                return;
            };
            let _ = sock.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            let _ = tokio::io::copy_bidirectional(&mut sock, &mut upstream).await;
        });
    }
}

pub(super) async fn dispatch_probe(method: &str, params: &serde_json::Value) -> serde_json::Value {
    match method {
        "net.http_probe" => http_probe(params).await,
        "relay.probe" => serde_json::json!({ "results": relay_probe(params).await }),
        _ => unreachable!("dispatch 收口处已白名单"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// http_probe 经 socks5 出口链访问目标：真实拨号链路（本机→socks5→目标）。
    #[tokio::test]
    async fn http_probe_via_socks5_reaches_target() {
        // 目标 HTTP 服务：任何请求回 204。
        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_port = http.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let Ok((mut s, _)) = http.accept().await else { return };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf).await;
                    let _ = s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await;
                });
            }
        });
        // socks5 服务
        let socks = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = socks.local_addr().unwrap().port();
        tokio::spawn(mini_socks5(socks));

        let r = http_probe(&serde_json::json!({
            "url": format!("http://127.0.0.1:{http_port}/"),
            "timeout_ms": 3000,
            "socks5": { "server": "127.0.0.1", "port": socks_port },
        }))
        .await;
        assert_eq!(r["ok"], serde_json::Value::Bool(true), "经 socks5 探测应成功: {r}");
        assert!(r["ms"].as_u64().is_some(), "应有耗时读数: {r}");
    }

    /// 诊断聚合：成功样本取均值、超时计丢包、全超时判不通。
    #[test]
    fn probe_summary_averages_successes_and_counts_loss() {
        let (ok, avg, loss) = summarize_probe(&[Some(5), Some(7), None]);
        assert!(ok);
        assert_eq!(avg, 6);
        assert!((loss - 100.0 / 3.0).abs() < 0.01);
        let (ok, avg, loss) = summarize_probe(&[None, None, None]);
        assert!(!ok, "全超时 = 不通");
        assert_eq!((avg, loss), (0, 100.0));
        let (ok, avg, loss) = summarize_probe(&[Some(10)]);
        assert_eq!((ok, avg, loss), (true, 10, 0.0), "count=1 与旧版单发语义一致");
    }
}
