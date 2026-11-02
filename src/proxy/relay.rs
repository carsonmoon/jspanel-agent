//! Realm 转发（M5 + 信封批次）：realm-api 单进程 + 进程内多实例执行器。
//!
//! 报文：{"units":[{"id","config","sha256"}...], "sha256"}。id = 规则 id、
//! "<规则id>-exit"（隧道出口半边）或占位 "main"；config 是 EndpointConf 的
//! **JSON 字符串**（hub 端 canonical 序列化，sha256 对该字符串算——agent 校验
//! 后原样转发给 realm 的 HTTP API，字段序不经过中间人）。执行器不再是
//! 「写文件+systemd 逐单元重启」，而是对 realm 进程内实例做 GET 对比 →
//! POST/PUT/DELETE/start——改/停/删单条规则不重启任何进程，其他实例的
//! 连接零感知（PR #160 的单进程模型，2026-11-01 拍板替换逐 unit 多进程）。
//! 机器级聚合指纹 units_aggregate 落盘 envelope.hash，心跳以它对账——口径
//! 与 hub 侧同一定义，两仓 golden 测试锁死。

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use super::{hex, run_cmd, systemd, unit_active};

/// realm-api（PR #160 monitor fork）构建的发布仓与钉死版本。本仓同时挂着
/// agent 的 v1.x tag，releases/latest 会挑错——realm 固定取此 tag，升级 =
/// 改这里 + 推新 realm-api-v* tag（CI 自动构建发布，见 realm-api/）。
pub const REALM_REPO: &str = "carsonmoon/jspanel-agent";
pub const REALM_API_VERSION: &str = "2.9.8-m1";

fn realm_bin() -> PathBuf {
    super::singbox::base_dir().join("bin").join("realm")
}

pub(super) fn bin_installed() -> bool {
    realm_bin().is_file()
}

/// realm 二进制 --version 的第二列（status 帧的 realm_version）。
pub(super) async fn version_string() -> String {
    if !realm_bin().is_file() {
        return String::new();
    }
    tokio::process::Command::new(realm_bin())
        .arg("--version")
        .output()
        .await
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().nth(1).unwrap_or("").to_owned())
        .unwrap_or_default()
}

/// realm-api 进程（systemd 单元或 dev 子进程）是否在跑。仅状态探测：
/// 调用方（status 帧）自行叠加「已安装」条件。
pub(super) async fn api_process_active() -> bool {
    if systemd() {
        unit_active("monitor-realm-api").await
    } else {
        realm_children()
            .lock()
            .unwrap()
            .get_mut(REALM_API_CHILD)
            .map(|c| c.try_wait().map_or(true, |w| w.is_none()))
            .unwrap_or(false)
    }
}

/// 每个 unit 一套目录：instances/<id>/realm.toml(+.hash)。id = 规则 id 或
/// 占位 "main"（待命占位沿用旧 main 布局，旧部署零迁移）。
fn realm_instances_dir() -> PathBuf {
    super::singbox::base_dir().join("instances")
}

fn realm_unit_dir(id: &str) -> PathBuf {
    realm_instances_dir().join(id)
}

fn realm_config() -> PathBuf {
    realm_unit_dir("main").join("realm.toml")
}

/// 机器级信封指纹落点（relay.apply 新协议写，旧协议不写）。
fn realm_envelope_hash_path() -> PathBuf {
    realm_instances_dir().join("envelope.hash")
}

/// unit id 只允许三种形态：占位 "main"、规则 id（纯数字，≤19 位）、隧道
/// 出口半边 `<规则id>-exit`（hub 的 render_relay_instances 按此渲染）。
/// hub 是可信端，但这是路径拼接入口——设卡防逃逸（instances/<id>/）。
/// 评审修复（2026-11-02）：曾只放行纯数字，出口半边整包 apply 被拒。
fn valid_unit_id(id: &str) -> bool {
    let (id, is_exit) = match id.strip_suffix("-exit") {
        Some(base) => (base, true),
        None => (id, false),
    };
    id == "main" && !is_exit || (!id.is_empty() && id.len() <= 19 && id.chars().all(|c| c.is_ascii_digit()))
}

/// 机器级指纹：信封优先（新协议），回落 main 的单文件指纹（旧协议/过渡期）。
/// 旧协议 apply 会清信封指纹，两格式互斥不并存。
pub(super) fn realm_hash() -> String {
    if let Ok(s) = std::fs::read_to_string(realm_envelope_hash_path()) {
        let s = s.trim();
        if !s.is_empty() {
            return s.to_owned();
        }
    }
    std::fs::read_to_string(realm_config().with_extension("toml.hash"))
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

/// 非 systemd 环境的 realm 子进程槽：unit id → child（dev/联调用；生产交给
/// systemd 模板单元 monitor-realm@<id>）。
fn realm_children() -> &'static Mutex<std::collections::BTreeMap<String, tokio::process::Child>> {
    static C: OnceLock<Mutex<std::collections::BTreeMap<String, tokio::process::Child>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
}

async fn relay_install(version: Option<String>) -> Result<String> {
    // 版本固定取 REALM_API_VERSION（fork 构建带 -m1 后缀，故校验放行连字符）；
    // 本仓混 tag，releases/latest 语义不可用。
    let version = match version {
        Some(v) => super::fetch::validate_version(super::fetch::VersionRule::Relaxed, &v)?,
        None => REALM_API_VERSION.to_owned(),
    };
    let target = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-musl",
        ("linux", "aarch64") => "aarch64-unknown-linux-musl",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        (os, arch) => bail!("暂不支持 {os}/{arch} 自动安装 Realm"),
    };
    let name = format!("realm-{target}.tar.gz");
    // tag 前缀 realm-api-（本仓混 agent tag，realm 发表的 tag 统一带此前缀）
    let url = format!("https://github.com/{REALM_REPO}/releases/download/realm-api-v{version}/{name}");
    let bytes = super::fetch::fetch_release(&url, 180, "realm").await?;
    super::fetch::install_binary(&bytes, &realm_bin(), "realm").await?;
    let out = tokio::process::Command::new(realm_bin()).arg("--version").output().await?;
    let v = String::from_utf8_lossy(&out.stdout).split_whitespace().nth(1).unwrap_or("").to_owned();
    Ok(v)
}

/// 只确保 realm 单元在跑，不碰配置文件（ensure_started poke 的落点）。
/// 逐 unit：盘上每个有指纹文件的 unit 都确保 active（幂等——已在跑的不碰）。
async fn ensure_realm_started() -> Result<()> {
    if realm_applied().is_empty() {
        return Ok(());
    }
    let active = if systemd() {
        unit_active("monitor-realm-api").await
    } else {
        realm_children()
            .lock()
            .unwrap()
            .get_mut(REALM_API_CHILD)
            .map(|c| c.try_wait().map_or(true, |w| w.is_none()))
            .unwrap_or(false)
    };
    if active {
        return Ok(());
    }
    if systemd() {
        match run_cmd("systemctl", &["start", "monitor-realm-api"]).await {
            Ok(out) if out.status.success() => eprintln!("[proxy] realm-api unit poked back up"),
            Ok(out) => eprintln!(
                "[proxy] systemctl start monitor-realm-api failed: exit {}, {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            Err(e) => eprintln!("[proxy] systemctl start monitor-realm-api failed: {e}"),
        }
    } else {
        spawn_realm_api_child().await?;
    }
    Ok(())
}

/// 重启（或首次拉起）单个 realm 单元；非 systemd 环境回落到直接 spawn 子进程。
/// 成功与否都记一行：拉活/应用链路曾整段静默，服务停了双方都报 ok
/// （is-active 退出码 bug，eac4e56），从这行起 journald 里可见真实动作。
async fn restart_realm_unit(id: &str) {
    if systemd() {
        let unit = format!("monitor-realm@{id}");
        match run_cmd("systemctl", &["restart", &unit]).await {
            Ok(out) if out.status.success() => eprintln!("[proxy] realm unit {id} restarted"),
            // systemctl 跑了但退出非零（如单元被 mask）同样是失败——退出码
            // 语义与 unit_active 同一课。
            Ok(out) => eprintln!(
                "[proxy] systemctl restart {unit} failed: exit {}, {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            Err(e) => eprintln!("[proxy] systemctl restart {unit} failed: {e}"),
        }
    } else {
        let old = realm_children().lock().unwrap().remove(id);
        if let Some(mut c) = old {
            let _ = c.kill().await;
        }
        match spawn_realm_child_unit(id) {
            Ok(()) => eprintln!("[proxy] realm child {id} restarted"),
            Err(e) => eprintln!("[proxy] realm child {id} spawn failed: {e:#}"),
        }
    }
}

/// 停止单个 realm 单元（dev 环境顺带把子进程槽清掉）。
async fn stop_realm_unit(id: &str) {
    if systemd() {
        let _ = run_cmd("systemctl", &["stop", &format!("monitor-realm@{id}")]).await;
    } else {
        // 先取出再杀：MutexGuard 不能跨 await（futex 自死锁课的同族问题）。
        let removed = realm_children().lock().unwrap().remove(id);
        if let Some(mut c) = removed {
            let _ = c.kill().await;
        }
    }
}

/// dev 环境拉起单个 unit 的 realm 子进程（配置路径按 unit 目录）。
fn spawn_realm_child_unit(id: &str) -> Result<()> {
    let child = tokio::process::Command::new(realm_bin())
        .arg("-c")
        .arg(realm_unit_dir(id).join("realm.toml"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("无法启动 realm")?;
    realm_children().lock().unwrap().insert(id.to_owned(), child);
    Ok(())
}

/// 盘上现存 unit id 全集：instances/ 下含 realm.toml 或其指纹文件的目录
/// （valid_unit_id 过滤——envelope.hash 等杂项文件与非目录条目一律跳过）。
fn realm_unit_ids_on_disk() -> Vec<String> {
    let mut ids = Vec::new();
    let Ok(rd) = std::fs::read_dir(realm_instances_dir()) else {
        return ids;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if !valid_unit_id(&name) {
            continue;
        }
        let p = e.path();
        if p.join("realm.toml").is_file() || p.join("realm.toml.hash").is_file() {
            ids.push(name);
        }
    }
    ids.sort();
    ids
}

/// API 端口恒回环（fork 补丁也在服务端钉死了 127.0.0.1，双保险）。
/// dev 模式 realm api 子进程在槽里的键。
const REALM_API_CHILD: &str = "api";

fn realm_api_port() -> u16 {
    18080
}

fn realm_api_key_path() -> PathBuf {
    realm_instances_dir().join("realm-api.key")
}

fn realm_api_store_path() -> PathBuf {
    realm_instances_dir().join("realm-api.json")
}

fn realm_api_conf_path() -> PathBuf {
    realm_instances_dir().join("realm-api.conf.json")
}

/// 最后成功 apply 的期望清单（id → sha256）落点。
fn realm_applied_path() -> PathBuf {
    realm_instances_dir().join("realm-api.applied.json")
}

/// 最后一次成功 apply 的期望清单（id → sha256）：心跳徽标数据源 + 「进程该
/// 不该在跑」的判据（空清单 = 运维显式停服/无腿，poke 不拉活）。
fn realm_applied() -> serde_json::Map<String, serde_json::Value> {
    serde_json::from_str(&std::fs::read_to_string(realm_applied_path()).unwrap_or_default())
        .unwrap_or_default()
}

fn realm_applied_write(map: &serde_json::Map<String, serde_json::Value>) -> Result<()> {
    std::fs::create_dir_all(realm_instances_dir())?;
    std::fs::write(realm_applied_path(), serde_json::to_string_pretty(map)?)?;
    Ok(())
}

fn random_hex32() -> String {
    use std::io::Read;
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).expect("无法读 /dev/urandom");
    hex(&b)
}

/// realm 实例 API 的抽象：HTTP 实现打回环，测试用内存桩。
trait RealmApi {
    /// (id, config Value, status Value)。status 是字符串 "Running"/"Stopped"
    /// 或 {"Failed": "..."}（外部标签枚举）。
    async fn list(&self) -> Result<Vec<(String, serde_json::Value, serde_json::Value)>>;
    async fn create(&self, id: &str, config: &serde_json::Value) -> Result<()>;
    async fn update(&self, id: &str, config: &serde_json::Value) -> Result<()>;
    async fn delete(&self, id: &str) -> Result<()>;
    async fn start(&self, id: &str) -> Result<()>;
}

struct HttpRealmApi {
    key: String,
}

impl RealmApi for HttpRealmApi {
    async fn list(&self) -> Result<Vec<(String, serde_json::Value, serde_json::Value)>> {
        let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;
        let v: serde_json::Value = client
            .get(format!("http://127.0.0.1:{}/instances", realm_api_port()))
            .header("X-API-Key", &self.key)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|i| {
                        Some((
                            i["id"].as_str()?.to_owned(),
                            i.get("config").cloned().unwrap_or_default(),
                            i.get("status").cloned().unwrap_or_default(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default())
    }
    async fn create(&self, id: &str, config: &serde_json::Value) -> Result<()> {
        let mut body = config.clone();
        body["id"] = serde_json::json!(id);
        let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;
        let r = client
            .post(format!("http://127.0.0.1:{}/instances", realm_api_port()))
            .header("X-API-Key", &self.key)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        let _ = r;
        Ok(())
    }
    async fn update(&self, id: &str, config: &serde_json::Value) -> Result<()> {
        let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;
        client
            .put(format!("http://127.0.0.1:{}/instances/{id}", realm_api_port()))
            .header("X-API-Key", &self.key)
            .json(config)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
    async fn delete(&self, id: &str) -> Result<()> {
        let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;
        client
            .delete(format!("http://127.0.0.1:{}/instances/{id}", realm_api_port()))
            .header("X-API-Key", &self.key)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
    async fn start(&self, id: &str) -> Result<()> {
        let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;
        client
            .post(format!("http://127.0.0.1:{}/instances/{id}/start", realm_api_port()))
            .header("X-API-Key", &self.key)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

/// 纯函数 diff（对账核心，单测锁语义）：desired/actual 均为
/// (id, config Value, sha)。config 以 serde_json::Value 相等判（键序无关）；
/// actual 的 status 非 Running 且 config 一致 → start（Failed 残留句柄由
/// fork 补丁在重生前 abort）。
type InstanceDiff =
    (Vec<(String, serde_json::Value)>, Vec<(String, serde_json::Value)>, Vec<String>, Vec<String>);

fn plan_instance_diff(
    desired: &[(String, serde_json::Value, String)],
    actual: &[(String, serde_json::Value, serde_json::Value)],
) -> InstanceDiff {
    let actual_map: std::collections::BTreeMap<&str, &serde_json::Value> =
        actual.iter().map(|(id, cfg, _)| (id.as_str(), cfg)).collect();
    let status_of = |id: &str| -> Option<&serde_json::Value> {
        actual.iter().find(|(aid, _, _)| aid == id).map(|(_, _, st)| st)
    };
    let mut create = Vec::new();
    let mut update = Vec::new();
    let mut start = Vec::new();
    for (id, cfg, _sha) in desired {
        match actual_map.get(id.as_str()) {
            None => create.push((id.clone(), cfg.clone())),
            Some(have) if have == &cfg => {
                if status_of(id).map(|s| s.as_str() != Some("Running")).unwrap_or(true) {
                    start.push(id.clone());
                }
            }
            Some(_) => update.push((id.clone(), cfg.clone())),
        }
    }
    let delete: Vec<String> = actual
        .iter()
        .filter(|(id, _, _)| !desired.iter().any(|(did, _, _)| did == id))
        .map(|(id, _, _)| id.clone())
        .collect();
    (create, update, start, delete)
}

/// 旧协议（整份 toml→monitor-realm@main）的模板单元：ExecStart 走 %i。内容
/// 有变才写+daemon-reload。仅旧 hub 兼容期使用；新 hub 的信封 apply 会退役
/// 整个模板（retire_legacy_realm_units）。
async fn ensure_realm_template() {
    if !systemd() {
        return;
    }
    let unit = format!(
        "[Unit]\nDescription=monitor realm relay %i\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={} -c {}/instances/%i/realm.toml\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n",
        realm_bin().display(),
        super::singbox::base_dir().display(),
    );
    let path = Path::new("/etc/systemd/system/monitor-realm@.service");
    let needs_write = match std::fs::read_to_string(path) {
        Ok(old) => old != unit,
        Err(_) => true,
    };
    if !needs_write {
        return;
    }
    if let Err(e) = std::fs::write(path, &unit) {
        eprintln!("[proxy] realm unit template write failed: {e}");
        return;
    }
    let _ = run_cmd("systemctl", &["daemon-reload"]).await;
    eprintln!("[proxy] realm unit template updated (%i)");
}

/// systemd 单元（monitor-realm-api）+ API key + 全局配置，内容幂等写。
/// 全局 network 留空：realm 自带 tcp+udp 默认，实例的 network 覆盖由 hub
/// 渲染时显式给出——不留 take_field 合并的口径分叉。
async fn ensure_realm_api_unit() -> Result<String> {
    let key_path = realm_api_key_path();
    let key = match std::fs::read_to_string(&key_path) {
        Ok(k) if k.trim().len() >= 32 => k.trim().to_owned(),
        _ => {
            let k = random_hex32();
            std::fs::create_dir_all(realm_instances_dir())?;
            std::fs::write(&key_path, &k)?;
            k
        }
    };
    // FullConf 的 endpoints 无 serde default（PR 原样），JSON 全局配置必须显式带空数组。
    let conf = r#"{"log":{"level":"warn"},"network":{},"endpoints":[]}"#;
    std::fs::write(realm_api_conf_path(), conf)?;
    if systemd() {
        let unit = format!(
            "[Unit]\nDescription=monitor realm-api (instance HTTP API)\nAfter=network-online.target\n\n[Service]\nType=simple\nEnvironment=REALM_API_KEY={key}\nEnvironment=REALM_INSTANCE_STORE={}\nExecStart={} api --port {} -c {}\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n",
            realm_api_store_path().display(),
            realm_bin().display(),
            realm_api_port(),
            realm_api_conf_path().display(),
        );
        let path = Path::new("/etc/systemd/system/monitor-realm-api.service");
        let needs = match std::fs::read_to_string(path) {
            Ok(old) => old != unit,
            Err(_) => true,
        };
        if needs {
            std::fs::write(path, &unit)?;
            let _ = run_cmd("systemctl", &["daemon-reload"]).await;
            eprintln!("[proxy] monitor-realm-api unit written");
        }
    }
    Ok(key)
}

/// dev 环境拉起 realm api 子进程（key/store 从盘上配置读）。
async fn spawn_realm_api_child() -> Result<()> {
    let key = std::fs::read_to_string(realm_api_key_path()).map(|k| k.trim().to_owned()).unwrap_or_default();
    let old = realm_children().lock().unwrap().remove(REALM_API_CHILD);
    if let Some(mut c) = old {
        let _ = c.kill().await;
    }
    let child = tokio::process::Command::new(realm_bin())
        .arg("api")
        .arg("--port")
        .arg(realm_api_port().to_string())
        .env("REALM_API_KEY", key)
        .env("REALM_INSTANCE_STORE", realm_api_store_path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("无法启动 realm api")?;
    realm_children().lock().unwrap().insert(REALM_API_CHILD.into(), child);
    eprintln!("[proxy] realm api child started");
    Ok(())
}

/// 拉起 realm-api 进程并等 API 就绪（首次 apply 必须可连）。
async fn ensure_realm_api_running(key: &str) -> Result<()> {
    if systemd() {
        if !unit_active("monitor-realm-api").await {
            run_cmd("systemctl", &["restart", "monitor-realm-api"]).await?;
            eprintln!("[proxy] realm-api unit started");
        }
    } else {
        let alive = realm_children()
            .lock()
            .unwrap()
            .get_mut(REALM_API_CHILD)
            .map(|c| c.try_wait().map_or(true, |w| w.is_none()))
            .unwrap_or(false);
        if !alive {
            spawn_realm_api_child().await?;
        }
    }
    let probe = HttpRealmApi { key: key.to_owned() };
    for _ in 0..25 {
        if probe.list().await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    bail!("realm-api 已启动但 API 未就绪（18080）")
}

/// 旧多进程（monitor-realm@<id>）一次性退役：停所有实例单元、删模板与
/// realm 配置文件（instances/<id>/ 与 sing-box 共住，只删 realm 的两份文件，
/// 目录空了顺手摘——2026-11-01 整目录 rm 事故的规矩）。幂等：模板不在即跳过。
async fn retire_legacy_realm_units() {
    if !Path::new("/etc/systemd/system/monitor-realm@.service").exists() {
        return;
    }
    for id in realm_unit_ids_on_disk() {
        let _ = run_cmd("systemctl", &["stop", &format!("monitor-realm@{id}")]).await;
        let dir = realm_unit_dir(&id);
        let _ = std::fs::remove_file(dir.join("realm.toml"));
        let _ = std::fs::remove_file(dir.join("realm.toml.hash"));
        let _ = std::fs::remove_dir(&dir);
    }
    let _ = std::fs::remove_file("/etc/systemd/system/monitor-realm@.service");
    let _ = run_cmd("systemctl", &["daemon-reload"]).await;
    eprintln!("[proxy] 旧 monitor-realm@* 单元已退役（realm-api 单进程接管）");
}

/// 机器级信封 apply：整包校验 → 退役旧多进程 → 确保 realm-api 进程在跑 →
/// GET 对比 → 执行 diff → 落盘 applied 清单与聚合指纹。任何一步失败都不半
/// 途而废——对账心跳 60s 后重推整包。
async fn relay_apply_envelope(units: Vec<serde_json::Value>, want_aggregate: &str) -> Result<String> {
    let mut expected: Vec<(String, serde_json::Value, String)> = Vec::new(); // (id, config, sha256)
    for u in &units {
        let id = u["id"].as_str().context("unit 缺少 id")?;
        if !valid_unit_id(id) {
            bail!("非法 unit id：{id}");
        }
        // config 是 canonical JSON 字符串（hub 端序列化），sha256 对该串算，
        // 原样 parse 后转发——字段序不经过中间人。
        let cfg_str = u["config"].as_str().context("unit {id} 缺少 config")?;
        let want = u["sha256"].as_str().unwrap_or_default();
        let got = hex(&Sha256::digest(cfg_str.as_bytes()));
        if !want.is_empty() && want != got {
            bail!("unit {id} 配置指纹不符：期望 {want}，收到 {got}");
        }
        let cfg: serde_json::Value =
            serde_json::from_str(cfg_str).with_context(|| format!("unit {id} config 非法 JSON"))?;
        expected.push((id.to_owned(), cfg, got.to_owned()));
    }
    let refs: Vec<(&str, &str)> = expected.iter().map(|(id, _, sha)| (id.as_str(), sha.as_str())).collect();
    let aggregate = units_aggregate(&refs);
    if !want_aggregate.is_empty() && want_aggregate != aggregate {
        bail!("信封聚合指纹不符：期望 {want_aggregate}，收到 {aggregate}");
    }
    // 二进制必须是带 api 子命令的 fork 构建：版本不含 REALM_API_VERSION
    // （机器上残留旧官方版）就自装钉死版本——只查 is_file() 会把旧版当
    // 新版，unit 起不来循环失败。
    if realm_bin().is_file() {
        let v = tokio::process::Command::new(realm_bin())
            .arg("--version")
            .output()
            .await
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        if !v.contains(REALM_API_VERSION) {
            eprintln!("[proxy] realm 二进制非 API 构建（{v}），自装 {REALM_API_VERSION}");
            relay_install(None).await?;
        }
    } else {
        relay_install(None).await?;
    }

    let key = ensure_realm_api_unit().await?;
    retire_legacy_realm_units().await;
    ensure_realm_api_running(&key).await?;

    let api = HttpRealmApi { key };
    apply_envelope_via_api(&api, &expected).await?;

    let mut map = serde_json::Map::new();
    for (id, _, sha) in &expected {
        map.insert(id.clone(), serde_json::json!(sha));
    }
    realm_applied_write(&map)?;
    std::fs::write(realm_envelope_hash_path(), &aggregate)?;
    Ok(aggregate)
}

/// diff 执行（API 注入，测试用内存桩）。操作失败即返回错误——对账重推整包。
async fn apply_envelope_via_api(
    api: &impl RealmApi,
    expected: &[(String, serde_json::Value, String)],
) -> Result<()> {
    let actual = api.list().await?;
    let (create, update, start, delete) = plan_instance_diff(expected, &actual);
    for (id, cfg) in &create {
        api.create(id, cfg).await?;
        eprintln!("[proxy] realm instance {id} created");
    }
    for (id, cfg) in &update {
        api.update(id, cfg).await?;
        eprintln!("[proxy] realm instance {id} updated");
    }
    for id in &start {
        api.start(id).await?;
        eprintln!("[proxy] realm instance {id} started");
    }
    for id in &delete {
        api.delete(id).await?;
        eprintln!("[proxy] realm instance {id} deleted");
    }
    Ok(())
}

/// 机器级聚合指纹：unit 按 id 升序，拼接 "id\nsha256\n" 后取 sha256。
/// 空清单 = sha256("")。与 hub 侧（monitor/src/proxy.rs units_aggregate）
/// 逐字同口径——改这里必须同步改那边，golden 测试会拦。
fn units_aggregate(units: &[(&str, &str)]) -> String {
    let mut sorted: Vec<(&str, &str)> = units.to_vec();
    sorted.sort();
    let mut buf = String::new();
    for (id, sha) in sorted {
        buf.push_str(id);
        buf.push('\n');
        buf.push_str(sha);
        buf.push('\n');
    }
    hex(&Sha256::digest(buf.as_bytes()))
}

async fn relay_apply(body: String, desired_running: bool, hash: &str) -> Result<()> {
    if body.is_empty() {
        // 空配置的语义唯一：desired_running=false，停服务清文件。「空体+true」
        // 曾是 hub 侧语义分叉的遗物——本侧自造占位写盘，指纹与空期望永不相等，
        // 每 60s 心跳重推并重启 realm；占位的定义与下发已收归 hub 独占
        // （relay_expected，2026-10-27 收口），此组合成为协议错误。
        if desired_running {
            bail!("空配置必须带 desired_running=false（期望停服务清理）；占位待命由 hub 以显式配置下发");
        }
        stop_realm_unit("main").await;
        let _ = std::fs::remove_file(realm_config());
        let _ = std::fs::remove_file(realm_config().with_extension("toml.hash"));
        // 格式互斥：退回旧协议时清信封指纹，否则陈旧聚合会让 hub 对账永不对。
        let _ = std::fs::remove_file(realm_envelope_hash_path());
        return Ok(());
    }
    tokio::fs::create_dir_all(realm_config().parent().expect("parent")).await?;
    tokio::fs::write(realm_config(), &body).await?;
    std::fs::write(realm_config().with_extension("toml.hash"), hash)?;
    ensure_realm_template().await;
    restart_realm_unit("main").await;
    Ok(())
}

/// 每 unit 的 {sha256, active} 快照：指纹读盘上 <unit>/realm.toml.hash，
/// active 走 realm HTTP API 的实例状态（进程不在/查询失败 → 全部 inactive，
/// 对账的 poke 会把进程拉回来）。sha 照报，不阻塞心跳。
pub(super) async fn realm_units_snapshot() -> serde_json::Value {
    let applied = realm_applied();
    let mut map = serde_json::Map::new();
    let api_list: Vec<(String, serde_json::Value, serde_json::Value)> = {
        let key =
            std::fs::read_to_string(realm_api_key_path()).map(|k| k.trim().to_owned()).unwrap_or_default();
        if key.is_empty() {
            Default::default()
        } else {
            HttpRealmApi { key }.list().await.unwrap_or_default()
        }
    };
    for (id, sha) in &applied {
        let sha = sha.as_str().unwrap_or_default().to_owned();
        let active = api_list
            .iter()
            .find(|(aid, _, _)| aid == id)
            .map(|(_, _, st)| st.as_str() == Some("Running"))
            .unwrap_or(false);
        map.insert(id.clone(), serde_json::json!({ "sha256": sha, "active": active }));
    }
    // ∪ 语义：API 侧存在但不在 applied 里的实例（漂移/手工建）也要上报——
    // sha 置空串即「与期望不符」的信号，hub 对账按聚合不等重推收编。
    for (id, _, st) in api_list {
        if !map.contains_key(&id) {
            let active = st.as_str() == Some("Running");
            map.insert(id, serde_json::json!({ "sha256": "", "active": active }));
        }
    }
    serde_json::Value::Object(map)
}

/// supervisor 的一拍（每 2s，proxy::supervisor 的 realm 腿）：有期望实例且
/// dev 子进程不在就重新拉起。spawn 是同步调用（异步 fn 内无 await 点），
/// 失败只影响下一拍对账——与 sing-box 腿的退避语义一致。
pub(super) fn supervise_tick() {
    if !realm_applied().is_empty() && realm_bin().is_file() {
        let dead = !realm_children()
            .lock()
            .unwrap()
            .get_mut(REALM_API_CHILD)
            .map(|c| c.try_wait().map_or(true, |w| w.is_none()))
            .unwrap_or(false);
        if dead {
            tokio::spawn(spawn_realm_api_child());
        }
    }
}

// ---- proxy.rs 分发入口的壳（命名对齐方法族，逻辑原样）----

pub(super) async fn install(version: Option<String>) -> Result<String> {
    relay_install(version).await
}

pub(super) async fn ensure_started() -> Result<()> {
    ensure_realm_started().await
}

pub(super) async fn apply_envelope(units: Vec<serde_json::Value>, want_aggregate: &str) -> Result<String> {
    relay_apply_envelope(units, want_aggregate).await
}

pub(super) async fn apply_legacy(body: String, desired_running: bool, hash: &str) -> Result<()> {
    relay_apply(body, desired_running, hash).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MONITOR_PROXY_DIR 是进程级环境变量：所有隔离落点的测试共用
    /// proxy::testutil::ENV_LOCK 串行执行，防止并行测试互相改掉对方的环境。
    use crate::proxy::testutil::ENV_LOCK;

    /// 空配置语义唯一性：desired_running=false 才是合法组合（停服务清文件）；
    /// true 是 hub 侧语义分叉遗物，现为协议错误。MONITOR_PROXY_DIR 隔离文件
    /// 落点，其余测试不读该变量、无并行干扰。
    #[tokio::test]
    async fn empty_relay_config_must_carry_desired_off() {
        let _env = ENV_LOCK.lock().await;
        let dir = std::env::temp_dir().join(format!("monitor-agent-relay-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("MONITOR_PROXY_DIR", &dir);
        std::fs::create_dir_all(realm_config().parent().unwrap()).unwrap();
        std::fs::write(realm_config(), "old-config").unwrap();
        std::fs::write(realm_config().with_extension("toml.hash"), "old-hash").unwrap();

        let err = relay_apply(String::new(), true, "").await.unwrap_err();
        assert!(err.to_string().contains("desired_running"), "空体+true 是协议错误: {err}");
        assert!(realm_config().exists(), "协议错误不碰盘上文件");

        relay_apply(String::new(), false, "").await.unwrap();
        assert!(!realm_config().exists(), "合法语义：配置文件清除");
        assert!(!realm_config().with_extension("toml.hash").exists(), "指纹文件清除");

        std::env::remove_var("MONITOR_PROXY_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 聚合指纹 golden 向量：与 hub 侧 monitor/src/proxy.rs 的同名测试同
    /// 向量同期望值——两仓口径锁死，一侧改动另一侧必红。
    #[test]
    fn units_aggregate_matches_golden_vector() {
        let ones = "1".repeat(64);
        let twos = "2".repeat(64);
        let units = [("17", ones.as_str()), ("main", twos.as_str())];
        assert_eq!(
            units_aggregate(&units),
            "58ebda98f681be3f9a61c270a8374bf990fcf9cf50b0262cc426f308f7c86509"
        );
        assert_eq!(
            units_aggregate(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "空清单 = sha256(\"\")"
        );
    }

    /// 信封 apply 落盘与清理：期望 unit 写入 instances/<id>/；期望集外的旧
    /// 实例 diff 语义（内存桩跑真执行器）：新建/收敛零操作/配置变更=update/
    /// 停止=start/期望外=delete。envelope 落盘簿记在 E2E 验证。
    #[tokio::test]
    async fn instance_diff_creates_updates_starts_deletes() {
        let api = MockRealmApi::default();
        let cfg_a = serde_json::json!({"listen": "0.0.0.0:10001", "remote": "10.0.0.1:80"});
        let cfg_b = serde_json::json!({"listen": "0.0.0.0:10001", "remote": "10.0.0.2:80"});
        let desired = |pairs: Vec<(&str, serde_json::Value)>| {
            pairs
                .into_iter()
                .map(|(id, cfg)| {
                    let sha = hex(&Sha256::digest(cfg.to_string().as_bytes()));
                    (id.to_owned(), cfg, sha)
                })
                .collect::<Vec<_>>()
        };

        // ops 跨 apply 累积，断言取每轮增量。
        macro_rules! apply_and_expect {
            ($want:expr, $expect:expr, $msg:expr) => {{
                let n0 = api.ops().len();
                apply_envelope_via_api(&api, &desired($want)).await.unwrap();
                assert_eq!(&api.ops()[n0..], $expect, "{}", $msg);
            }};
        }
        let ph = serde_json::json!({"listen": "127.0.0.1:19998", "remote": "127.0.0.1:9"});
        apply_and_expect!(vec![("17", cfg_a.clone())], &["create:17".to_owned()], "空机首推=创建");
        apply_and_expect!(vec![("17", cfg_a.clone())], &[] as &[String], "收敛态零操作");
        apply_and_expect!(vec![("17", cfg_b.clone())], &["update:17".to_owned()], "配置变更=update");
        apply_and_expect!(
            vec![("17", cfg_b.clone()), ("main", ph.clone())],
            &["create:main".to_owned()],
            "新增实例=创建"
        );
        apply_and_expect!(vec![("main", ph.clone())], &["delete:17".to_owned()], "期望外实例=删除");
        api.stop("main");
        apply_and_expect!(vec![("main", ph)], &["start:main".to_owned()], "配置一致但停止=start");
    }

    /// realm-api 实例的内存桩：记操作序列、维护 (id, config, status) 表。
    #[derive(Default)]
    struct MockRealmApi {
        items: std::sync::Mutex<Vec<(String, serde_json::Value, serde_json::Value)>>,
        ops: std::sync::Mutex<Vec<String>>,
    }
    impl MockRealmApi {
        fn ops(&self) -> Vec<String> {
            self.ops.lock().unwrap().clone()
        }
        fn stop(&self, id: &str) {
            let mut items = self.items.lock().unwrap();
            if let Some(it) = items.iter_mut().find(|(i, _, _)| i == id) {
                it.2 = serde_json::json!("Stopped");
            }
        }
    }
    impl RealmApi for MockRealmApi {
        async fn list(&self) -> anyhow::Result<Vec<(String, serde_json::Value, serde_json::Value)>> {
            Ok(self.items.lock().unwrap().clone())
        }
        async fn create(&self, id: &str, config: &serde_json::Value) -> anyhow::Result<()> {
            self.ops.lock().unwrap().push(format!("create:{id}"));
            self.items.lock().unwrap().push((id.to_owned(), config.clone(), serde_json::json!("Running")));
            Ok(())
        }
        async fn update(&self, id: &str, config: &serde_json::Value) -> anyhow::Result<()> {
            self.ops.lock().unwrap().push(format!("update:{id}"));
            let mut items = self.items.lock().unwrap();
            if let Some(it) = items.iter_mut().find(|(i, _, _)| i == id) {
                it.1 = config.clone();
            }
            Ok(())
        }
        async fn delete(&self, id: &str) -> anyhow::Result<()> {
            self.ops.lock().unwrap().push(format!("delete:{id}"));
            self.items.lock().unwrap().retain(|(i, _, _)| i != id);
            Ok(())
        }
        async fn start(&self, id: &str) -> anyhow::Result<()> {
            self.ops.lock().unwrap().push(format!("start:{id}"));
            let mut items = self.items.lock().unwrap();
            if let Some(it) = items.iter_mut().find(|(i, _, _)| i == id) {
                it.2 = serde_json::json!("Running");
            }
            Ok(())
        }
    }

    /// unit id 白名单回归（评审 2026-11-02）：出口半边 <digits>-exit 必须放行
    /// ——曾只放行纯数字，隧道出口腿整包 apply 被拒。
    #[test]
    fn valid_unit_id_accepts_exit_suffix() {
        assert!(valid_unit_id("17"));
        assert!(valid_unit_id("17-exit"));
        assert!(valid_unit_id("main"));
        assert!(!valid_unit_id("exit"));
        assert!(!valid_unit_id("-exit"));
        assert!(!valid_unit_id("17-exit-x"));
        assert!(!valid_unit_id("../evil"));
        assert!(!valid_unit_id("17-exit/../evil"));
    }

    /// 非法 unit id（路径逃逸形态）整包拒绝，盘上零写入。
    #[tokio::test]
    async fn envelope_apply_rejects_bad_unit_id_and_touches_nothing() {
        let _env = ENV_LOCK.lock().await;
        let dir = std::env::temp_dir().join(format!("monitor-agent-relay-badid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("MONITOR_PROXY_DIR", &dir);

        let units = serde_json::json!([{ "id": "../evil", "config": "x", "sha256": "" }]);
        let err = relay_apply_envelope(units.as_array().unwrap().clone(), "").await.unwrap_err();
        assert!(err.to_string().contains("非法 unit id"), "应拒绝非法 id: {err}");
        assert!(!realm_envelope_hash_path().exists(), "拒绝时不落任何盘上状态");

        std::env::remove_var("MONITOR_PROXY_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
