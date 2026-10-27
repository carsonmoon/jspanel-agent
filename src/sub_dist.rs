//! 订阅分发入口（兜底 + 分散负载）：agent 上的极简 HTTP 监听，只服务
//! `GET /api/conv-sub?token=…`。命中缓存直接返回；未命中回源 hub 刷新缓存；
//! hub 不可达时用 7 天内的落盘快照兜底。订阅关掉分发/停用后 hub 回 403，
//! agent 清缓存并下发失效占位——立即断供。
//!
//! 手写 HTTP/1.1 而非引入 axum：单 GET 端点，Connection: close，读请求头
//! 至 `\r\n\r\n` 即可。全部 IO 用超时包裹——agent 跑在 current_thread
//! 运行时上，慢客户端不得阻塞 WS/探针。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// 快照兜底有效期：超过后不再用旧内容应付客户端（防永久过期配置）。
const SNAPSHOT_TTL_SECS: i64 = 7 * 24 * 3600;
/// 单连接读/写预算：慢客户端到点即断，不占 current_thread 运行时。
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// 回源 hub 的预算。
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

const PLACEHOLDER: &str = "mixed-port: 7890\nmode: rule\nlog-level: warning\nproxies:\n  - name: 订阅已失效\n    type: socks5\n    server: 127.0.0.1\n    port: 9\nproxy-groups:\n  - name: 订阅已失效\n    type: select\n    proxies:\n      - DIRECT\nrules:\n  - MATCH,DIRECT\n";

#[derive(Serialize, Deserialize, Default)]
struct Cache(HashMap<String, Entry>);

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    body: String,
    saved: i64,
}

struct Inner {
    server: String,
    path: PathBuf,
    cache: Mutex<Cache>,
    client: reqwest::Client,
}

/// 分发服务句柄：clone 进每个连接任务。
#[derive(Clone)]
pub struct Dist {
    port: u16,
    inner: Arc<Inner>,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Dist {
    /// `port` 为 0 时调用方不应启动；`path` 是落盘快照文件。
    /// （insecure 只作用于 WS 通道；回源走同一 server 的普通 http(s)，不涉
    /// 自签场景，曾作为死字段存过。）
    pub fn new(port: u16, server: String, path: PathBuf) -> Self {
        let cache = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_str(&String::from_utf8_lossy(&b)).ok())
            .unwrap_or_default();
        let client = reqwest::Client::builder().timeout(FETCH_TIMEOUT).build().expect("reqwest client");
        Self { port, inner: Arc::new(Inner { server, path, cache: Mutex::new(cache), client }) }
    }

    /// 监听循环。绑定失败只报错不 panic——分发是附加能力，不拖垮监控。
    pub async fn run(&self) {
        match tokio::net::TcpListener::bind(("0.0.0.0", self.port)).await {
            Ok(listener) => {
                eprintln!("subscription distribution listening on 0.0.0.0:{}", self.port);
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            let this = self.clone();
                            tokio::spawn(async move {
                                let _ = this.handle(stream).await;
                            });
                        }
                        Err(e) => eprintln!("distribution accept: {e}"),
                    }
                }
            }
            Err(e) => eprintln!("subscription distribution disabled: bind {}: {e}", self.port),
        }
    }

    async fn handle(&self, mut stream: tokio::net::TcpStream) -> anyhow::Result<()> {
        // 读请求头至 \r\n\r\n（8KB 上限）。
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = tokio::time::timeout(IO_TIMEOUT, tokio::io::AsyncReadExt::read(&mut stream, &mut chunk))
                .await
                .context("read timeout")?
                .context("read")?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                break;
            }
        }
        let request = String::from_utf8_lossy(&buf);
        let line = request.lines().next().unwrap_or_default();
        let path = line.split_whitespace().nth(1).unwrap_or_default();
        // 用户中心页入口：agent 只当门牌，302 跳到面板 HTTPS 的 /u 页。
        if path == "/u" || path.starts_with("/u/") || path.starts_with("/u?") {
            let target = format!("{}/u{}", self.inner.server.trim_end_matches('/'), &path[2..]);
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            tokio::time::timeout(
                IO_TIMEOUT,
                tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()),
            )
            .await
            .context("write timeout")?
            .context("write")?;
            return Ok(());
        }
        // 双路径：客户订阅（/api/sub，新）与旧方案链接（/api/conv-sub，兼容期
        // 保留——hub 已下线该端点，回源会 404 走兜底/占位）。缓存键含路径命名
        // 空间，两套 token 互不串。
        let origin_path = if path.starts_with("/api/conv-sub?") {
            Some("/api/conv-sub")
        } else if path.starts_with("/api/sub?") {
            Some("/api/sub")
        } else {
            None
        };
        let (status, content_type, body) = match origin_path {
            Some(prefix) => match path
                .split('?')
                .nth(1)
                .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("token=")))
            {
                Some(tok) => self.serve_token(prefix, tok).await,
                None => (404, "text/plain; charset=utf-8", "not found".to_string()),
            },
            None => (404, "text/plain; charset=utf-8", "not found".to_string()),
        };
        let reason = match status {
            200 => "OK",
            403 => "Forbidden",
            404 => "Not Found",
            _ => "Service Unavailable",
        };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        tokio::time::timeout(
            IO_TIMEOUT,
            tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()),
        )
        .await
        .context("write timeout")?
        .context("write")?;
        Ok(())
    }

    /// 决策顺序：回源（成功刷新缓存）→ 403 清缓存断供 → 7 天内快照兜底 → 失效占位。
    async fn serve_token(&self, origin_path: &str, token: &str) -> (u16, &'static str, String) {
        let url = format!("{}{}?token={}", self.inner.server.trim_end_matches('/'), origin_path, token);
        let key = format!("{origin_path}|{token}");
        let request = self.inner.client.get(&url).header("x-sub-dist", "agent");
        if let Ok(resp) = request.send().await {
            let status = resp.status().as_u16();
            match status {
                200 => {
                    let body = resp.text().await.unwrap_or_default();
                    self.cache_update(&key, &body);
                    return (200, "text/yaml; charset=utf-8", body);
                }
                403 => {
                    self.cache_remove(&key);
                    return (403, "text/plain; charset=utf-8", "agent distribution disabled".into());
                }
                _ => {}
            }
        }
        // 兜底：7 天内的落盘/内存快照
        let cache = self.inner.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = cache.0.get(&key) {
            if now() - e.saved <= SNAPSHOT_TTL_SECS && !e.body.is_empty() {
                return (200, "text/yaml; charset=utf-8", e.body.clone());
            }
        }
        (200, "text/yaml; charset=utf-8", PLACEHOLDER.to_string())
    }

    fn cache_update(&self, token: &str, body: &str) {
        let entry = Entry { body: body.to_owned(), saved: now() };
        {
            let mut cache = self.inner.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.0.insert(token.to_owned(), entry);
            let snapshot = serde_json::to_string(&*cache).ok();
            drop(cache);
            if let Some(text) = snapshot {
                let _ = std::fs::write(&self.inner.path, text); // 落盘失败只影响下次重启的兜底
            }
        }
    }

    fn cache_remove(&self, token: &str) {
        let mut cache = self.inner.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.0.remove(token);
        let snapshot = serde_json::to_string(&*cache).ok();
        drop(cache);
        if let Some(text) = snapshot {
            let _ = std::fs::write(&self.inner.path, text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("sub-dist-{}-{}.json", tag, std::process::id()))
    }

    #[test]
    fn cache_survives_reload_and_corruption_is_tolerated() {
        let path = tmp_path("roundtrip");
        let _ = std::fs::remove_file(&path);
        let d = Dist::new(0, "https://hub".into(), path.clone());
        d.cache_update("/api/sub|tok", "BODY");
        // 重建实例：从盘上恢复缓存
        let d2 = Dist::new(0, "https://hub".into(), path.clone());
        let cache = d2.inner.cache.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(cache.0.get("/api/sub|tok").unwrap().body, "BODY");
        drop(cache);
        // 损坏文件按空缓存容忍
        std::fs::write(&path, "garbage!!").unwrap();
        let d3 = Dist::new(0, "https://hub".into(), path.clone());
        assert!(d3.inner.cache.lock().unwrap_or_else(|e| e.into_inner()).0.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    /// server 指向不可达端口：回源必败，走兜底分支。
    #[tokio::test]
    async fn stale_snapshots_expire_after_ttl() {
        let path = tmp_path("ttl");
        let _ = std::fs::remove_file(&path);
        let d = Dist::new(0, "http://127.0.0.1:1".into(), path.clone());
        let now = now();
        {
            let mut cache = d.inner.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.0.insert("/api/sub|fresh".into(), Entry { body: "FRESH".into(), saved: now });
            cache.0.insert(
                "/api/sub|stale".into(),
                Entry { body: "STALE".into(), saved: now - SNAPSHOT_TTL_SECS - 10 },
            );
        }
        // 7 天内：兜底返回快照
        let (status, _, body) = d.serve_token("/api/sub", "fresh").await;
        assert_eq!((status, body.as_str()), (200, "FRESH"));
        // 超期：返回失效占位
        let (status, _, body) = d.serve_token("/api/sub", "stale").await;
        assert_eq!(status, 200);
        assert_eq!(body, PLACEHOLDER);
        let _ = std::fs::remove_file(&path);
    }
}
