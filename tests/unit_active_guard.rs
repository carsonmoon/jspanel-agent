//! retro 产物（2026-10-27）：is-active 退出码盲区的机械防线。
//!
//! `systemctl is-active` 的语义在退出码里（--quiet 无输出，inactive=exit 3），
//! `matches!(run_cmd(...), Ok(_))` 只证明命令执行了——曾在 src/proxy.rs 复发
//! 4 处（eac4e56 修复），hub 的拉活 poke 到达即空转、双方都报 ok。
//! 本测试把「直接调用 is-active」限定在 unit_active 一处：新代码要问单元
//! 状态就调 unit_active，写第二处直接调用会在 cargo test 变红。

const SRC: &str = include_str!("../src/proxy.rs");

#[test]
fn systemctl_is_active_only_inside_unit_active() {
    assert_eq!(
        SRC.matches("\"is-active\"").count(),
        1,
        "直接调 systemctl is-active 只允许存在于 unit_active 里；问单元状态请调 unit_active"
    );
    assert!(SRC.contains("async fn unit_active"), "unit_active 必须存在");
    assert!(SRC.contains("status.success()"), "unit_active 必须以退出码（status.success）判活");
}
