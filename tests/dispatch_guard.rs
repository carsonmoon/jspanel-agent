//! retro 产物（2026-11-02）：hub→agent 方法分发的机械防线。
//!
//! 白名单曾三次漏前缀（net.* / gost.* / shaper.* 同款事故）：帧落进
//! `Some(_) => {}` 被静默丢弃，hub 侧只见 30s 超时，无日志无回帧——
//! shaper.* 一例至修复时仍是坏的（远程限速从未生效）。
//!
//! 修复后 main.rs 的 route() 是白名单的单一事实源，未知方法回
//! UNKNOWN_METHOD 帧（fail fast）。本测试锁两件事：
//! ①静默丢弃臂不再出现；②deny 回帧语义不被回退。
//! 新增方法族漏放行由 route 的单测与 deny 回帧兜底（事故已从
//! 「查无此帧」降为「秒级可见」），此处不追正确性、只追不回退。

const MAIN: &str = include_str!("../src/main.rs");

#[test]
fn dispatch_never_silently_drops_a_method() {
    // 静默臂的旧形态：Some(_) => {}（含等价变体 Some(_)=>{}）。
    assert!(
        !MAIN.contains("Some(_) => {}") && !MAIN.contains("Some(_)=>{}"),
        "分发循环禁止静默丢弃臂——未知方法必须回 UNKNOWN_METHOD 帧（shaper.* 三例同款事故的教训）"
    );
    // deny 回帧语义存在且被点名。
    assert!(MAIN.contains("UNKNOWN_METHOD"), "未知方法必须回 UNKNOWN_METHOD error 帧，hub 秒级可见");
    // 白名单单一事实源：分发必须经 route()，而非重新长出 starts_with 链。
    // 计数锚定在 route() 函数体内（fn route 到 enum Handler 之间）：
    // proxy./relay./net./gost./shaper. 共 5 个前缀 + route./exec. 两臂 = 7。
    let (a, b) = (MAIN.find("fn route(").unwrap(), MAIN.find("enum Handler").unwrap());
    let route_body = &MAIN[a..b];
    let starts_with_arms = route_body.matches("starts_with(").count();
    assert_eq!(
        starts_with_arms, 7,
        "方法族前缀只允许收口在 route() 一处（现 7 个：proxy./relay./net./gost./shaper./route./exec.）；\
         新方法族在 route() 加臂，勿在分发处另写前缀链"
    );
}
