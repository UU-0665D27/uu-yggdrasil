use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum TunSetting {
    Enabled(bool),
    Config(TunFile),
    Name(String),
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct TunFile {
    pub name: Option<String>,
    pub mtu: Option<u16>,
}
