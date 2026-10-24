//! Загрузка и генерация конфигурации узла.
//!
//! Поддерживаются TOML и JSON. TOML — основной формат (как у
//! yggdrasil-совместимых демонов), JSON оставлен для совместимости.

use crate::{NodeInfoConfig, TunConfig, YggdrasilConfig, config::tun::TunSetting};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::Value;
use std::{
    error::Error,
    fmt::Write as _,
    fs,
    io::{self, Write as _},
    net::SocketAddr,
    path::Path,
};
pub mod tun;

/// Разобранный конфиг: готовый узел плюс пиры и listen-адреса.
pub struct LoadedConfig {
    pub yggdrasil: YggdrasilConfig,
    pub peers: Vec<String>,
    pub listen: Vec<SocketAddr>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FileConfig {
    #[serde(alias = "PrivateKey")]
    private_key: Option<String>,
    #[serde(alias = "Peers")]
    peers: Vec<String>,
    #[serde(alias = "Listen")]
    listen: Vec<String>,

    #[serde(alias = "tun_enabled")]
    tun_enabled: bool,
    #[serde(alias = "Tun", alias = "TUN")]
    tun: Option<TunSetting>,
    #[serde(alias = "IfName")]
    if_name: Option<String>,
    #[serde(alias = "IfMTU")]
    if_mtu: Option<u16>,

    #[serde(alias = "NodeInfo")]
    node_info: Option<Value>,
    #[serde(alias = "NodeInfoPrivacy")]
    node_info_privacy: Option<bool>,
    #[serde(alias = "IncludePeers")]
    include_peers: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct RemoteControl {
    #[serde(alias = "enabled")]
    pub enabled: bool,
    /// Порт TCP-консоли внутри yggdrasil; 0 — не запускать консоль.
    #[serde(alias = "port")]
    pub port: u16,
}

/// Загрузить конфиг из TOML или JSON.
///
/// `allow_tun` выключает TUN независимо от файла (режим echo).
/// `default_tun` включает TUN, если в конфиге про него ничего нет.
///
/// # Errors
/// Ошибка чтения/разбора файла, ключа или listen-адреса.
pub fn load_config(path: &Path) -> Result<LoadedConfig, Box<dyn Error>> {
    let text = fs::read_to_string(path)?;
    let file = parse_file_config(&text, path)?;

    let mut yggdrasil = YggdrasilConfig::default();
    if let Some(key) = file.private_key.as_deref() {
        yggdrasil.private_key = parse_private_key(key)?;
    }
    yggdrasil.tun = build_tun(&file);
    yggdrasil.node_info = build_node_info(
        file.node_info.as_ref(),
        file.node_info_privacy,
        file.include_peers,
    );

    let peers = file
        .peers
        .iter()
        .map(|uri| normalize_peer_uri(uri))
        .collect::<Result<Vec<_>, _>>()?;

    let listen = file
        .listen
        .iter()
        .map(|uri| parse_listen(uri))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LoadedConfig {
        yggdrasil,
        peers,
        listen,
    })
}

/// Сгенерировать TOML-конфиг с новым случайным ключом.
///
/// # Errors
/// Ошибка системного генератора случайных чисел.
pub fn generate_toml() -> io::Result<String> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(io::Error::other)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key();
    let private_key = format!("{}{}", hex(&seed), hex(public_key.as_bytes()));

    Ok(format!(
        r#"# uu-yggdrasil configuration file
#
# TOML. Do not share the private key.
# 64 bytes (128 hex) = ed25519 seed || public key.

private_key = "{private_key}"

# Outbound peers, e.g. "tcp://host:port?key=<hex>&priority=0".
peers = []

# Inbound peer listeners. Port 0 picks a free port at startup.
listen = ["tcp://0.0.0.0:0"]

# TUN interface. Use "none" to disable it.
if_name = "yggdrasil0"
if_mtu = 65535

# Set to true to omit build/platform fields from node_info.
# node_info_privacy = false

# Custom node_info fields, e.g. name = "my-node".
[node_info]
"#
    ))
}

/// Напечатать сгенерированный конфиг или записать его в файл.
///
/// `None` или путь `-` означает stdout. При записи файл создаётся с правами
/// `0600` на Unix.
///
/// # Errors
/// Ошибка генерации или записи; при `no_replace` — файл уже существует.
pub fn generate_to(path: Option<&Path>, no_replace: bool) -> Result<(), Box<dyn Error>> {
    let text = generate_toml()?;
    let Some(path) = path else {
        print!("{text}");
        return Ok(());
    };
    if path == Path::new("-") {
        print!("{text}");
        return Ok(());
    }
    if no_replace && path.exists() {
        return Err(format!("{} already exists", path.display()).into());
    }
    write_private_file(path, text.as_bytes())?;
    eprintln!("generated {}", path.display());
    Ok(())
}

/// Hex-представление байтов.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn parse_file_config(text: &str, path: &Path) -> Result<FileConfig, Box<dyn Error>> {
    let json = path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
        || text.trim_start().starts_with('{');
    if json {
        serde_json::from_str(text).map_err(|error| format!("{}: {error}", path.display()).into())
    } else {
        toml::from_str(text).map_err(|error| format!("{}: {error}", path.display()).into())
    }
}

fn write_private_file(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn parse_private_key(value: &str) -> Result<SigningKey, Box<dyn Error>> {
    let value = value.trim();
    // Go хранит 64 байта: seed || public key. Для подписи нужен только seed.
    let seed_hex = if value.len() == 128 {
        &value[..64]
    } else {
        value
    };
    if seed_hex.len() != 64 {
        return Err("private_key must be 32 or 64 bytes of hex".into());
    }
    let mut seed = [0u8; 32];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&seed_hex[index * 2..index * 2 + 2], 16)
            .map_err(|error| format!("bad private_key hex: {error}"))?;
    }
    Ok(SigningKey::from_bytes(&seed))
}

fn normalize_peer_uri(uri: &str) -> Result<String, Box<dyn Error>> {
    let uri = uri.trim();
    if uri.is_empty() {
        return Err("peer URI must not be empty".into());
    }
    if uri.contains("://") {
        Ok(uri.to_owned())
    } else {
        Ok(format!("tcp://{uri}"))
    }
}

fn parse_listen(uri: &str) -> Result<SocketAddr, Box<dyn Error>> {
    let uri = uri.trim();
    let address = uri.strip_prefix("tcp://").unwrap_or(uri);
    address
        .parse()
        .map_err(|error| format!("bad listen address {uri:?}: {error}").into())
}

fn build_tun(file: &FileConfig) -> Option<TunConfig> {
    if !file.tun_enabled {
        return None;
    }
    let fallback = TunConfig::default();
    let configured_name = file.if_name.as_deref();
    let configured_mtu = file.if_mtu.unwrap_or(fallback.mtu);

    match &file.tun {
        Some(TunSetting::Enabled(false)) => None,
        Some(TunSetting::Enabled(true)) => {
            let name = configured_name.map_or(fallback.name, normalize_tun_name);
            make_tun(&name, configured_mtu)
        }
        Some(TunSetting::Name(name)) => make_tun(name, configured_mtu),
        Some(TunSetting::Config(config)) => {
            let name = config
                .name
                .clone()
                .or_else(|| configured_name.map(ToOwned::to_owned))
                .unwrap_or(fallback.name);
            make_tun(&name, config.mtu.unwrap_or(configured_mtu))
        }
        None => make_tun(&fallback.name, configured_mtu),
    }
}

fn normalize_tun_name(name: &str) -> String {
    if name.eq_ignore_ascii_case("auto") {
        TunConfig::default().name
    } else {
        name.to_owned()
    }
}

fn make_tun(name: &str, mtu: u16) -> Option<TunConfig> {
    let normalized = normalize_tun_name(name);
    if matches!(
        normalized.to_ascii_lowercase().as_str(),
        "none" | "disabled" | "off"
    ) {
        None
    } else {
        Some(TunConfig {
            name: normalized,
            mtu,
        })
    }
}

fn build_node_info(
    raw: Option<&Value>,
    privacy: Option<bool>,
    include_peers: Option<bool>,
) -> NodeInfoConfig {
    let mut node_info = NodeInfoConfig::default();
    if let Some(Value::Object(map)) = raw {
        let structured = map.contains_key("fields")
            || map.contains_key("privacy")
            || map.contains_key("include_peers");
        if structured {
            if let Some(Value::Object(fields)) = map.get("fields") {
                node_info.fields.clone_from(fields);
            }
            if let Some(value) = map.get("privacy").and_then(Value::as_bool) {
                node_info.privacy = value;
            }
            if let Some(value) = map.get("include_peers").and_then(Value::as_bool) {
                node_info.include_peers = value;
            }
        } else {
            // Go-подобный NodeInfo без обёртки: это просто поля.
            node_info.fields.clone_from(map);
        }
    }
    if let Some(value) = privacy {
        node_info.privacy = value;
    }
    if let Some(value) = include_peers {
        node_info.include_peers = value;
    }
    node_info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_toml_is_loadable() {
        let text = generate_toml().expect("generate");
        let file = parse_file_config(&text, Path::new("generated.toml")).expect("parse");
        let key = parse_private_key(file.private_key.as_deref().expect("key")).expect("key");
        assert_eq!(file.listen, vec!["tcp://0.0.0.0:0"]);
        assert_eq!(file.if_mtu, Some(65_535));
        assert_eq!(
            hex(key.verifying_key().as_bytes()),
            file.private_key.as_deref().expect("key")[64..]
        );
    }

    #[test]
    fn json_config_is_still_supported() {
        let text = r#"{
            "private_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "listen": ["127.0.0.1:0"],
            "tun": false
        }"#;
        let file = parse_file_config(text, Path::new("config.json")).expect("parse");
        assert_eq!(file.listen, vec!["127.0.0.1:0"]);
    }
}
