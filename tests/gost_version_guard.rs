//! GOST_VERSION 跨仓 golden（候选6）：agent 侧钉死的 gost 版本与 hub 侧
//! ensure 补装的期望版本必须同值——两侧漂移时 hub 按旧版本 ensure，agent
//! 装新版本，心跳对账各说各话。
//!
//! 实现方式仿 units_aggregate 先例（两仓同向量同期望的纯函数 + golden）：
//! 这里 include_str! 直接读 hub 仓源码 monitor/src/gost.rs，抓出其
//! GOST_VERSION 字面量与 agent 侧常量比对——hub 侧改动本测试即红。
//!
//! 布局前提：本测试只在两仓同级目录的检出布局下成立
//! （jspp/monitor 与 jspp/monitor-agent 同父目录，本地开发仓即如此）。
//! 独立检出 agent 仓时 ../monitor 不存在，编译即红——属预期：golden 的
//! 前提就是两仓可见。文件头注释即为此说明。
//!
//! 同步纪律（装机预装版本唯一事实源 = agent 钉死常量，HANDOFF 技术决策）：
//! 升级 gost = 改 agent 常量 + 同步 hub 常量 + 本测试锁死两侧。

const AGENT_GOST_VERSION: &str = "3.3.2";
const HUB_SRC: &str = include_str!("../../monitor/src/gost.rs");

#[test]
fn hub_gost_version_literal_matches_agent_constant() {
    // hub 侧声明形如：pub const GOST_VERSION: &str = "3.3.2";
    let line = HUB_SRC
        .lines()
        .find(|l| l.contains("pub const GOST_VERSION"))
        .expect("hub 仓 monitor/src/gost.rs 必须声明 pub const GOST_VERSION（找不到 = hub 侧常量被改名/移动，两仓版本同步防线失效）");
    let literal = line.split('"').nth(1).expect("GOST_VERSION 行应含字符串字面量");
    assert_eq!(
        literal, AGENT_GOST_VERSION,
        "hub 侧 GOST_VERSION 与 agent 钉死常量不一致：改版本必须两仓同步（agent 侧 src/proxy/gost.rs，hub 侧 monitor/src/gost.rs）"
    );
}
