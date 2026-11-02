//! gost/realm-api 回环 API 端口跨仓防线：gost 的热重载 API 与 realm-api 的
//! 实例 API 都钉死在环回上，曾经同用 127.0.0.1:18080——realm 实例模型
//! （2026-11-02）先占端口后，gost 同机 bind 失败崩溃循环（生产 one 实锤，
//! NRestarts=44）。本测试锁三点：
//!
//! 1. agent 侧 GOST_API 与 hub 侧 GOST_API_PORT 同值（热重载打的就是渲染
//!    出的地址，两侧漂移 = reload 永远 404/连接拒绝）；
//! 2. gost 端口 ≠ 18080（realm-api 的既有占用，两核心同机必须错开）；
//! 3. agent 侧 realm_api_port 字面量仍是 18080（换走了会静默断掉所有已
//!    部署 realm-api unit——unit 文件里 ExecStart 写的是旧端口）。
//!
//! 实现仿 gost_version_guard.rs：运行期读 ../monitor/src/gost.rs 与本仓
//! relay.rs 源码抓字面量；两仓同级布局才比对，CI 单仓检出跳过。

const AGENT_GOST_API: &str = "http://127.0.0.1:18081/config/reload";
const REALM_API_PORT: &str = "18080";

/// 从 `http://127.0.0.1:<port>/...` 形态的常量里抓端口段。
fn port_of(url: &str) -> u16 {
    let after_host = url.split("127.0.0.1:").nth(1).expect("GOST_API 常量应钉在 127.0.0.1 上");
    let digits: String = after_host.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().expect("GOST_API 常量应含数字端口")
}

fn hub_gost_rs() -> Option<String> {
    match std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../monitor/src/gost.rs")) {
        Ok(s) => Some(s),
        Err(_) => {
            eprintln!("跳过：../monitor 不存在（CI/独立检出单仓布局，无对照物）");
            None
        }
    }
}

#[test]
fn hub_gost_api_port_literal_matches_agent_constant() {
    let Some(hub_src) = hub_gost_rs() else { return };
    let line = hub_src
        .lines()
        .find(|l| l.contains("pub const GOST_API_PORT"))
        .expect("hub 仓 monitor/src/gost.rs 必须声明 pub const GOST_API_PORT（找不到 = 常量被改名/移动，两仓端口同步防线失效）");
    let literal = line.split_whitespace().last().expect("GOST_API_PORT 行应有值").replace(';', "");
    let port: u16 = literal.parse().expect("GOST_API_PORT 应是 u16 字面量");
    let agent_port = port_of(AGENT_GOST_API);
    assert_eq!(
        port, agent_port,
        "hub 侧 GOST_API_PORT 与 agent 侧 GOST_API 不一致：热重载打不到渲染出的地址，改端口必须两仓同步"
    );
}

#[test]
fn gost_api_port_must_avoid_realm_api_port() {
    let agent_port = port_of(AGENT_GOST_API);
    assert_ne!(
        agent_port.to_string(),
        REALM_API_PORT,
        "gost API 端口撞上 realm-api 的 18080：同机双核心 bind 冲突，gost 崩溃循环（one 实锤）"
    );
    if let Some(hub_src) = hub_gost_rs() {
        let line = hub_src
            .lines()
            .find(|l| l.contains("pub const GOST_API_PORT"))
            .expect("hub 仓必须声明 GOST_API_PORT");
        let literal = line.split_whitespace().last().expect("应有值").replace(';', "");
        assert_ne!(
            literal, REALM_API_PORT,
            "hub 侧 gost API 端口撞上 realm-api 的 18080：同机双核心 bind 冲突"
        );
    }
}

#[test]
fn realm_api_port_literal_is_stable() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/proxy/relay.rs"))
        .expect("relay.rs 必须存在");
    let line = src.lines().find(|l| l.contains("fn realm_api_port")).expect(
        "realm_api_port 函数必须还在（被改名/删除 = 已部署 realm-api unit 的 ExecStart 端口失去对照）",
    );
    assert!(line.contains("u16"), "realm_api_port 签名变化：确认 unit 兼容性后同步本测试");
    // 函数体紧跟下一行，形如 `    18080`。
    let idx = src.lines().position(|l| l.contains("fn realm_api_port")).unwrap();
    let body = src.lines().nth(idx + 1).unwrap_or("");
    assert_eq!(
        body.trim().trim_end_matches(',').replace('_', ""),
        REALM_API_PORT,
        "realm-api 端口改动会把所有已部署 unit（ExecStart 钉旧端口）静默断线；确要换端口必须走迁移"
    );
}
