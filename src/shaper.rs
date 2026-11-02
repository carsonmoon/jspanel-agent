//! 按协议限速的 agent 侧执行器：tc/HTB + IFB 在内核队列层对入站端口限速
//! （与 hub 的 src/shaper.rs 同一套语义的 agent 版本——两个 crate 各自独立，
//! 不共享代码是本仓库的既有形态）。每协议 = 每端口：
//! 下载 = 出口网卡 sport 匹配，上传 = ingress 重定向到 IFB 后 dport 匹配，
//! v4（flower ip）与 v6（flower ip6）各一套 filter，tcp/udp 各一条。
//!
//! 端口表持久化到 base_dir/shaper.json：agent 启动时重放，机器重启不丢
//! （tc 规则本身是内存态的）。

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::process::Command;

const IFB: &str = "portshaper-ifb0";
const PARENT_RATE: &str = "1000mbit";

#[derive(Debug, Deserialize, serde::Serialize)]
pub struct ShapedPort {
    pub port: i64,
    pub up: i64,
    pub down: i64,
}

fn state_path() -> std::path::PathBuf {
    crate::proxy::base_dir().join("shaper.json")
}

/// hub `shaper.apply` 的入口：全量端口表，幂等重建。
pub async fn apply(params: &serde_json::Value) -> Result<serde_json::Value> {
    let ports: Vec<ShapedPort> = serde_json::from_value(params.get("ports").cloned().context("缺少 ports")?)
        .context("端口表格式不对")?;
    let msg =
        tokio::task::spawn_blocking(move || apply_ports(&ports)).await.context("shaper 线程启动失败")??;
    Ok(serde_json::json!({ "message": msg }))
}

/// 启动重放：上次应用过的端口表原样重建（机器重启后 tc 是内存态，必须重放）。
pub async fn replay() {
    let Ok(text) = std::fs::read_to_string(state_path()) else { return };
    let Ok(ports) = serde_json::from_str::<Vec<ShapedPort>>(&text) else {
        eprintln!("[shaper] 状态文件损坏，忽略：{}", state_path().display());
        return;
    };
    if ports.is_empty() {
        return;
    }
    match tokio::task::spawn_blocking(move || apply_ports(&ports)).await {
        Ok(Ok(msg)) => eprintln!("[shaper] {msg}"),
        Ok(Err(e)) => eprintln!("[shaper] 启动重放失败：{e:#}"),
        Err(e) => eprintln!("[shaper] 启动重放线程失败：{e}"),
    }
}

/// root 挂 HTB：qdisc replace 不是幂等操作——HTB 已在 root 上时再 replace
/// 内核报「Change operation not supported」（生产 one 实锤），所以已挂就
/// 跳过；class/filter 的 replace 才有真幂等语义。default 99 恒定，重挂
/// 没有可变参数。（与 hub 仓 src/shaper.rs 同名同语义，两仓不共享代码是
/// 本仓库既有形态，改一处必须同步另一处。）
fn ensure_htb(nic: &str, handle: &str) -> Result<()> {
    // capture 模式恒走 replace 臂，让 golden 锁住 replace 的 argv 形状。
    #[cfg(test)]
    if tc_sink().is_some() {
        return tc(&[
            "qdisc",
            "replace",
            "dev",
            nic,
            "root",
            "handle",
            &format!("{handle}:"),
            "htb",
            "default",
            "99",
        ]);
    }
    let out = Command::new("tc").args(["qdisc", "show", "dev", nic]).output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let wanted = format!("htb {handle}:");
    if text.contains(&wanted) {
        return Ok(());
    }
    tc(&["qdisc", "replace", "dev", nic, "root", "handle", &format!("{handle}:"), "htb", "default", "99"])
}

fn tc(args: &[&str]) -> Result<()> {
    // 测试 seam：golden 测试锁 argv 形状（handle 必须是 "1:" 单参数这类拼接
    // 错误生产才炸、单测抓不住——argv 装配是唯一可提前锁死的层）。
    #[cfg(test)]
    if let Some(sink) = tc_sink() {
        sink.lock().unwrap().push(args.iter().map(|s| s.to_string()).collect());
        return Ok(());
    }
    let out = Command::new("tc")
        .args(args)
        .output()
        .context("服务器缺少 tc 命令（iproute2），请先安装：apt install -y iproute2")?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        if err.contains("Operation not permitted") || err.contains("Operation not supported") {
            bail!("tc 权限不足（{err}）：LXC/OpenVZ 容器无法限速，或缺少 CAP_NET_ADMIN")
        }
        bail!("tc {err}")
    }
}

/// golden 测试的 tc argv 收集器（仅测试编译进；生产恒 None 零开销）。
#[cfg(test)]
type TcSink = std::sync::Arc<std::sync::Mutex<Vec<Vec<String>>>>;

#[cfg(test)]
static TC_SINK: std::sync::Mutex<Option<TcSink>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn tc_sink() -> Option<TcSink> {
    TC_SINK.lock().unwrap().clone()
}

#[cfg(test)]
pub(crate) fn tc_capture() -> TcSink {
    let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    *TC_SINK.lock().unwrap() = Some(sink.clone());
    sink
}

fn ip(args: &[&str]) -> Result<String> {
    // 同 tc：capture 模式记 argv 不执行（link add/set 无输出可期待）。
    #[cfg(test)]
    if let Some(sink) = tc_sink() {
        sink.lock()
            .unwrap()
            .push(std::iter::once("ip".to_owned()).chain(args.iter().map(|s| s.to_string())).collect());
        return Ok(String::new());
    }
    let out = Command::new("ip").args(args).output().context("服务器缺少 ip 命令（iproute2）")?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        bail!("ip {} 失败：{}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim())
    }
}

fn detect_nic() -> Result<String> {
    let out = ip(&["-o", "route", "get", "1.1.1.1"])?;
    out.split_whitespace()
        .skip_while(|w| *w != "dev")
        .nth(1)
        .map(str::to_owned)
        .context("无法从路由表识别出口网卡")
}

fn teardown(nic: &str) -> Result<()> {
    // 只拆自己画的：root 是 handle 1: 的 htb 才动，绝不碰他人 qdisc。
    let qdisc = Command::new("tc").args(["qdisc", "show", "dev", nic]).output();
    if let Ok(out) = qdisc {
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("htb 1:") {
            tc(&["qdisc", "del", "dev", nic, "root"])?;
        }
        if text.contains("ingress") {
            let _ = tc(&["qdisc", "del", "dev", nic, "ingress"]);
        }
    }
    let _ = Command::new("ip").args(["link", "del", IFB]).output();
    let _ = std::fs::remove_file(state_path());
    Ok(())
}

fn apply_ports(ports: &[ShapedPort]) -> Result<String> {
    let nic = detect_nic()?;
    match build(&nic, ports) {
        Ok(()) => {
            std::fs::write(state_path(), serde_json::to_string_pretty(ports).context("序列化端口表")?)
                .context("写入限速状态文件失败")?;
            Ok(format!(
                "已在 {nic} 应用限速：{} 个端口（↑{} ↓{} Mbps）",
                ports.len(),
                ports.iter().map(|p| p.up).sum::<i64>(),
                ports.iter().map(|p| p.down).sum::<i64>()
            ))
        }
        // 半成品比没有更糟：任一步失败就整体拆掉，错误带给 hub。
        Err(e) => {
            teardown(&nic)?;
            Err(e)
        }
    }
}

fn build(nic: &str, ports: &[ShapedPort]) -> Result<()> {
    if ports.is_empty() {
        return teardown(nic);
    }
    // capture 模式恒走 add 臂，让 golden 锁住 ip link add 的 argv 形状。
    #[cfg(test)]
    let exists = tc_sink().is_none();
    #[cfg(not(test))]
    let exists = Command::new("ip").args(["link", "show", IFB]).output();
    #[cfg(not(test))]
    let exists = matches!(&exists, Ok(o) if o.status.success());
    if !exists {
        ip(&["link", "add", IFB, "type", "ifb"])
            .context("创建 IFB 设备失败：内核可能未加载 ifb 模块（modprobe ifb）")?;
    }
    ip(&["link", "set", IFB, "up"])?;

    // 下载方向：出口网卡 root HTB，default 99 让未托管流量不受影响。
    ensure_htb(nic, "1")?;
    tc(&[
        "class",
        "replace",
        "dev",
        nic,
        "parent",
        "1:",
        "classid",
        "1:1",
        "htb",
        "rate",
        PARENT_RATE,
        "ceil",
        PARENT_RATE,
    ])?;
    tc(&[
        "class",
        "replace",
        "dev",
        nic,
        "parent",
        "1:",
        "classid",
        "1:99",
        "htb",
        "rate",
        PARENT_RATE,
        "ceil",
        PARENT_RATE,
    ])?;
    // 上传方向：IFB 上的第二棵 HTB。
    ensure_htb(IFB, "2")?;
    tc(&[
        "class",
        "replace",
        "dev",
        IFB,
        "parent",
        "2:",
        "classid",
        "2:1",
        "htb",
        "rate",
        PARENT_RATE,
        "ceil",
        PARENT_RATE,
    ])?;
    tc(&[
        "class",
        "replace",
        "dev",
        IFB,
        "parent",
        "2:",
        "classid",
        "2:99",
        "htb",
        "rate",
        PARENT_RATE,
        "ceil",
        PARENT_RATE,
    ])?;
    tc(&["qdisc", "replace", "dev", nic, "handle", "ffff:", "ingress"])?;
    tc(&[
        "filter", "replace", "dev", nic, "parent", "ffff:", "matchall", "action", "mirred", "egress",
        "redirect", "dev", IFB,
    ])?;

    for (i, p) in ports.iter().enumerate() {
        let down_id = format!("1:{}", 101 + i);
        let up_id = format!("2:{}", 101 + i);
        if p.down > 0 {
            let rate = format!("{}mbit", p.down);
            tc(&[
                "class", "replace", "dev", nic, "parent", "1:1", "classid", &down_id, "htb", "rate", &rate,
                "ceil", &rate,
            ])?;
            // flower 的 L4 端口键不分 v4/v6（ip6src_port 不存在），v6 靠 protocol ipv6 区分
            for proto in ["ip", "ipv6"] {
                for ip_proto in ["tcp", "udp"] {
                    tc(&[
                        "filter",
                        "replace",
                        "dev",
                        nic,
                        "parent",
                        "1:",
                        "protocol",
                        proto,
                        "flower",
                        "ip_proto",
                        ip_proto,
                        "src_port",
                        &p.port.to_string(),
                        "classid",
                        &down_id,
                    ])?;
                }
            }
        }
        if p.up > 0 {
            let rate = format!("{}mbit", p.up);
            tc(&[
                "class", "replace", "dev", IFB, "parent", "2:1", "classid", &up_id, "htb", "rate", &rate,
                "ceil", &rate,
            ])?;
            for proto in ["ip", "ipv6"] {
                for ip_proto in ["tcp", "udp"] {
                    tc(&[
                        "filter",
                        "replace",
                        "dev",
                        IFB,
                        "parent",
                        "2:",
                        "protocol",
                        proto,
                        "flower",
                        "ip_proto",
                        ip_proto,
                        "dst_port",
                        &p.port.to_string(),
                        "classid",
                        &up_id,
                    ])?;
                }
            }
        }
    }

    std::fs::write(state_path(), serde_json::to_string_pretty(ports).context("序列化端口表")?)
        .context("写入限速状态文件失败")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_SEQ: AtomicUsize = AtomicUsize::new(0);

    /// tc/ip argv golden：限速命令序列的形状在此锁死。这些命令只在生产
    /// agent 里真跑，argv 拼接错误（ensure_htb 首版把 "1:" 拆成 "1" ":"
    /// 两个独立参数，单测全绿生产才炸）测试环境抓不住——唯一可提前锁
    /// 死的层就是 argv 装配本身。改 tc 序列必须同改 golden；两仓同名同
    /// 语义（hub 仓 src/shaper.rs），改一处必须同步另一处。
    #[test]
    fn build_emits_the_expected_tc_argv_sequence() {
        // state_path 落点走 MONITOR_PROXY_DIR（进程级环境变量，gost 测试
        // 同款纪律）：每测试独立临时目录 + ENV_LOCK 串行，互不踩。
        let dir =
            std::env::temp_dir().join(format!("shaper-golden-{}", DIR_SEQ.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        let _env = crate::proxy::testutil::ENV_LOCK.blocking_lock();
        let _guard = DirGuard { prev: std::env::var("MONITOR_PROXY_DIR").ok() };
        std::env::set_var("MONITOR_PROXY_DIR", &dir);

        let sink = tc_capture();
        let ports = vec![ShapedPort { port: 46154, up: 20, down: 20 }];
        build("eth1", &ports).expect("capture 模式 build 不触网");

        let got = sink.lock().unwrap().clone();
        let want: Vec<Vec<String>> = vec![
            // IFB 建立（capture 恒走 add 臂）+ 拉起。
            ip_vec(&["link", "add", "portshaper-ifb0", "type", "ifb"]),
            ip_vec(&["link", "set", "portshaper-ifb0", "up"]),
            // 下载方向 root HTB——handle 必须是 "1:" 单参数。
            tc_vec(&["qdisc", "replace", "dev", "eth1", "root", "handle", "1:", "htb", "default", "99"]),
            tc_vec(&[
                "class", "replace", "dev", "eth1", "parent", "1:", "classid", "1:1", "htb", "rate",
                "1000mbit", "ceil", "1000mbit",
            ]),
            tc_vec(&[
                "class", "replace", "dev", "eth1", "parent", "1:", "classid", "1:99", "htb", "rate",
                "1000mbit", "ceil", "1000mbit",
            ]),
            // 上传方向 IFB 上的第二棵 HTB。
            tc_vec(&[
                "qdisc",
                "replace",
                "dev",
                "portshaper-ifb0",
                "root",
                "handle",
                "2:",
                "htb",
                "default",
                "99",
            ]),
            tc_vec(&[
                "class",
                "replace",
                "dev",
                "portshaper-ifb0",
                "parent",
                "2:",
                "classid",
                "2:1",
                "htb",
                "rate",
                "1000mbit",
                "ceil",
                "1000mbit",
            ]),
            tc_vec(&[
                "class",
                "replace",
                "dev",
                "portshaper-ifb0",
                "parent",
                "2:",
                "classid",
                "2:99",
                "htb",
                "rate",
                "1000mbit",
                "ceil",
                "1000mbit",
            ]),
            // ingress 全量重定向到 IFB。
            tc_vec(&["qdisc", "replace", "dev", "eth1", "handle", "ffff:", "ingress"]),
            tc_vec(&[
                "filter",
                "replace",
                "dev",
                "eth1",
                "parent",
                "ffff:",
                "matchall",
                "action",
                "mirred",
                "egress",
                "redirect",
                "dev",
                "portshaper-ifb0",
            ]),
            // 下载腿：类 + v4/v6 × tcp/udp 四条 sport filter。
            tc_vec(&[
                "class", "replace", "dev", "eth1", "parent", "1:1", "classid", "1:101", "htb", "rate",
                "20mbit", "ceil", "20mbit",
            ]),
            tc_vec(&[
                "filter", "replace", "dev", "eth1", "parent", "1:", "protocol", "ip", "flower", "ip_proto",
                "tcp", "src_port", "46154", "classid", "1:101",
            ]),
            tc_vec(&[
                "filter", "replace", "dev", "eth1", "parent", "1:", "protocol", "ip", "flower", "ip_proto",
                "udp", "src_port", "46154", "classid", "1:101",
            ]),
            tc_vec(&[
                "filter", "replace", "dev", "eth1", "parent", "1:", "protocol", "ipv6", "flower", "ip_proto",
                "tcp", "src_port", "46154", "classid", "1:101",
            ]),
            tc_vec(&[
                "filter", "replace", "dev", "eth1", "parent", "1:", "protocol", "ipv6", "flower", "ip_proto",
                "udp", "src_port", "46154", "classid", "1:101",
            ]),
            // 上传腿：类 + 四条 dport filter（挂在 IFB 上）。
            tc_vec(&[
                "class",
                "replace",
                "dev",
                "portshaper-ifb0",
                "parent",
                "2:1",
                "classid",
                "2:101",
                "htb",
                "rate",
                "20mbit",
                "ceil",
                "20mbit",
            ]),
            tc_vec(&[
                "filter",
                "replace",
                "dev",
                "portshaper-ifb0",
                "parent",
                "2:",
                "protocol",
                "ip",
                "flower",
                "ip_proto",
                "tcp",
                "dst_port",
                "46154",
                "classid",
                "2:101",
            ]),
            tc_vec(&[
                "filter",
                "replace",
                "dev",
                "portshaper-ifb0",
                "parent",
                "2:",
                "protocol",
                "ip",
                "flower",
                "ip_proto",
                "udp",
                "dst_port",
                "46154",
                "classid",
                "2:101",
            ]),
            tc_vec(&[
                "filter",
                "replace",
                "dev",
                "portshaper-ifb0",
                "parent",
                "2:",
                "protocol",
                "ipv6",
                "flower",
                "ip_proto",
                "tcp",
                "dst_port",
                "46154",
                "classid",
                "2:101",
            ]),
            tc_vec(&[
                "filter",
                "replace",
                "dev",
                "portshaper-ifb0",
                "parent",
                "2:",
                "protocol",
                "ipv6",
                "flower",
                "ip_proto",
                "udp",
                "dst_port",
                "46154",
                "classid",
                "2:101",
            ]),
        ];
        assert_eq!(
            got, want,
            "tc/ip argv 序列漂移：确认内核语义后同步 golden（handle 形态/参数顺序是生产实跑的契约）"
        );
    }

    fn tc_vec(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    fn ip_vec(args: &[&str]) -> Vec<String> {
        std::iter::once("ip".to_owned()).chain(args.iter().map(|s| s.to_string())).collect()
    }

    /// 测试结束恢复 MONITOR_PROXY_DIR（ENV_LOCK 保证串行，恢复即安全）。
    struct DirGuard {
        prev: Option<String>,
    }
    impl Drop for DirGuard {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(v) => std::env::set_var("MONITOR_PROXY_DIR", v),
                None => std::env::remove_var("MONITOR_PROXY_DIR"),
            }
        }
    }
}
