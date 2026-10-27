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

fn tc(args: &[&str]) -> Result<()> {
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

fn ip(args: &[&str]) -> Result<String> {
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
    let exists = Command::new("ip").args(["link", "show", IFB]).output();
    let exists = matches!(&exists, Ok(o) if o.status.success());
    if !exists {
        ip(&["link", "add", IFB, "type", "ifb"])
            .context("创建 IFB 设备失败：内核可能未加载 ifb 模块（modprobe ifb）")?;
    }
    ip(&["link", "set", IFB, "up"])?;

    tc(&["qdisc", "replace", "dev", nic, "root", "handle", "1:", "htb", "default", "99"])?;
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
    tc(&["qdisc", "replace", "dev", IFB, "root", "handle", "2:", "htb", "default", "99"])?;
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
