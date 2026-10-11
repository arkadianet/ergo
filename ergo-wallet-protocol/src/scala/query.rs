use serde::Deserialize;

#[derive(Deserialize, Default)]
pub struct PageQuery {
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    50
}

#[derive(Deserialize)]
pub struct TxIdQuery {
    pub id: String,
}
