//! 发布包下载与二进制落位（install 三兄弟的共享件）：三个被管核心
//! （sing-box / realm / gost）的安装流程同为「版本校验 → 拼下载 URL →
//! 下载 → tar.gz 解包 → chmod 0755 → 原子落位」，差异只在版本校验器、
//! URL 模板与包内文件名——都在调用方，这里只收真正的公共段。

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};

/// 版本号校验器（install 的第一段）：显式传入的版本先过这里，防版本串
/// 混进 URL（路径注入）。三种口径：
/// - digits：数字与点（sing-box / gost 官方 tag）；
/// - relaxed：字母数字与点、连字符、≤32 位（realm fork 构建 2.9.8-m1）。
pub(crate) enum VersionRule {
    Digits,
    Relaxed,
}

pub(crate) fn validate_version(rule: VersionRule, version: &str) -> Result<String> {
    let v = version.trim().trim_start_matches('v').to_owned();
    let ok = match rule {
        VersionRule::Digits => !v.is_empty() && v.chars().all(|c| c.is_ascii_digit() || c == '.'),
        VersionRule::Relaxed => {
            !v.is_empty()
                && v.len() <= 32
                && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        }
    };
    if !ok {
        bail!("版本号格式不对：{v}");
    }
    Ok(v)
}

/// 下载发布包。只发 GET + 校验状态码；UA 固定 monitor-agent（GitHub 侧要求）。
pub(crate) async fn fetch_release(url: &str, timeout_secs: u64, ctx: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .context("构建下载客户端失败")?;
    let bytes = client
        .get(url)
        .header("User-Agent", "monitor-agent")
        .send()
        .await
        .with_context(|| format!("下载 {ctx} 失败"))?
        .error_for_status()
        .with_context(|| format!("下载 {ctx} 失败：远端返回错误"))?
        .bytes()
        .await
        .with_context(|| format!("读取 {ctx} 下载内容失败"))?;
    Ok(bytes.to_vec())
}

/// 二进制落位：tar.gz 解包找 `name` 文件 → 临时名 + 原子替换（避免覆盖运行
/// 中的二进制，Linux ETXTBSY）→ chmod 0755。
pub(crate) async fn install_binary(bytes: &[u8], bin: &Path, name: &str) -> Result<()> {
    tokio::fs::create_dir_all(bin.parent().expect("bin has a parent")).await?;
    let staging = bin.with_extension("new");
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes));
    let mut found = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        if entry.header().entry_type().is_file() && path.file_name().is_some_and(|n| n == name) {
            entry.unpack(&staging)?;
            found = true;
        }
    }
    if !found {
        let _ = tokio::fs::remove_file(&staging).await;
        bail!("压缩包中没有找到 {name} 可执行文件");
    }
    tokio::fs::rename(&staging, bin).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(bin, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

/// 常用 os/arch → 发布资产命名段（sing-box 与 gost 同款命名法）。os/arch
/// 之外的报错文案由调用方给（三处措辞历史不同，保持原样）。
pub(crate) fn os_arch_slug(os_err: &str, arch_err: &str) -> Result<(String, String)> {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        other => bail!("{os_err} {other}"),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => bail!("{arch_err} {other}"),
    };
    Ok((os.to_owned(), arch.to_owned()))
}
