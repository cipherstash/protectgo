use super::Error;
use cipherstash_client::schema::{
    column::{ArrayIndexMode, Index, IndexType, TokenFilter, Tokenizer},
    ColumnConfig, ColumnType,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, str::FromStr};

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Identifier {
    #[serde(rename = "t")]
    pub table: String,
    #[serde(rename = "c")]
    pub column: String,
}

impl Identifier {
    pub fn new<S>(table: S, column: S) -> Self
    where
        S: Into<String>,
    {
        let table = table.into();
        let column = column.into();

        Self { table, column }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Tables(HashMap<String, Table>);

impl IntoIterator for Tables {
    type Item = (String, Table);
    type IntoIter = std::collections::hash_map::IntoIter<String, Table>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Table(HashMap<String, Column>);

impl IntoIterator for Table {
    type Item = (String, Column);
    type IntoIter = std::collections::hash_map::IntoIter<String, Column>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct EncryptConfig {
    #[serde(rename = "v")]
    pub version: u32,
    pub tables: Tables,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
pub struct Column {
    #[serde(default)]
    cast_as: CastAs,
    #[serde(default)]
    indexes: Indexes,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CastAs {
    BigInt,
    Boolean,
    Date,
    Number,
    #[default]
    String,
    Text,
    Json,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq)]
pub struct Indexes {
    #[serde(rename = "ore")]
    ore_index: Option<OreIndexOpts>,
    #[serde(rename = "unique")]
    unique_index: Option<UniqueIndexOpts>,
    #[serde(rename = "match")]
    match_index: Option<MatchIndexOpts>,
    #[serde(rename = "ste_vec")]
    ste_vec_index: Option<SteVecIndexOpts>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct OreIndexOpts {}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct MatchIndexOpts {
    #[serde(default = "default_tokenizer")]
    tokenizer: Tokenizer,
    #[serde(default)]
    token_filters: Vec<TokenFilter>,
    #[serde(default = "default_k")]
    k: usize,
    #[serde(default = "default_m")]
    m: usize,
    #[serde(default)]
    include_original: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct SteVecIndexOpts {
    prefix: String,
    #[serde(default)]
    term_filters: Vec<TokenFilter>,
    #[serde(default)]
    array_index_mode: ArrayIndexMode,
}

fn default_tokenizer() -> Tokenizer {
    Tokenizer::Standard
}

fn default_k() -> usize {
    6
}

fn default_m() -> usize {
    2048
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct UniqueIndexOpts {
    #[serde(default)]
    token_filters: Vec<TokenFilter>,
}

impl From<CastAs> for ColumnType {
    fn from(value: CastAs) -> Self {
        match value {
            CastAs::BigInt => ColumnType::BigInt,
            CastAs::Boolean => ColumnType::Boolean,
            CastAs::Date => ColumnType::Date,
            CastAs::Number => ColumnType::Float,
            CastAs::String => ColumnType::Utf8Str,
            CastAs::Text => ColumnType::Utf8Str,
            CastAs::Json => ColumnType::JsonB,
        }
    }
}

impl FromStr for EncryptConfig {
    type Err = Error;

    fn from_str(data: &str) -> Result<Self, Self::Err> {
        let config = serde_json::from_str(data).map_err(Error::Parse)?;
        Ok(config)
    }
}

impl EncryptConfig {
    pub fn into_config_map(self) -> Result<HashMap<Identifier, ColumnConfig>, super::Error> {
        let mut map = HashMap::new();
        for (table_name, columns) in self.tables.into_iter() {
            for (column_name, column) in columns.into_iter() {
                let column_config = column.into_column_config(&table_name, &column_name)?;
                let key = Identifier::new(&table_name, &column_name);
                map.insert(key, column_config);
            }
        }
        Ok(map)
    }
}

impl Column {
    pub fn into_column_config(
        self,
        table_name: &str,
        column_name: &str,
    ) -> Result<ColumnConfig, super::Error> {
        // Validate ste_vec requires cast_as: json
        if self.indexes.ste_vec_index.is_some() && self.cast_as != CastAs::Json {
            return Err(super::Error::SteVecRequiresJsonCastAs {
                table: table_name.to_string(),
                column: column_name.to_string(),
                found_cast_as: cast_as_name(&self.cast_as).to_string(),
            });
        }

        let mut config = ColumnConfig::build(column_name.to_string()).casts_as(self.cast_as.into());

        if self.indexes.ore_index.is_some() {
            config = config.add_index(Index::new_ore());
        }

        if let Some(opts) = self.indexes.match_index {
            config = config.add_index(Index::new(IndexType::Match {
                tokenizer: opts.tokenizer,
                token_filters: opts.token_filters,
                k: opts.k,
                m: opts.m,
                include_original: opts.include_original,
            }));
        }

        if let Some(opts) = self.indexes.unique_index {
            config = config.add_index(Index::new(IndexType::Unique {
                token_filters: opts.token_filters,
            }))
        }

        if let Some(SteVecIndexOpts {
            prefix,
            term_filters,
            array_index_mode,
        }) = self.indexes.ste_vec_index
        {
            config = config.add_index(Index::new(IndexType::SteVec {
                prefix,
                term_filters,
                array_index_mode,
            }))
        }

        Ok(config)
    }
}

/// Get a human-readable name for CastAs value
fn cast_as_name(cast_as: &CastAs) -> &'static str {
    match cast_as {
        CastAs::BigInt => "bigint",
        CastAs::Boolean => "boolean",
        CastAs::Date => "date",
        CastAs::Number => "number",
        CastAs::String => "string",
        CastAs::Text => "text",
        CastAs::Json => "json",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn parse(json: serde_json::Value) -> HashMap<Identifier, ColumnConfig> {
        serde_json::from_value::<EncryptConfig>(json)
            .unwrap()
            .into_config_map()
            .unwrap()
    }

    #[test]
    fn column_with_empty_options_gets_defaults() {
        let json = json!({
            "v": 1,
            "tables": {
                "users": {
                    "email": {}
                }
            }
        });

        let encrypt_config = parse(json);

        let ident = Identifier::new("users", "email");

        let column = encrypt_config.get(&ident).expect("column exists");

        assert_eq!(column.cast_type, ColumnType::Utf8Str);
        assert!(column.indexes.is_empty());
    }

    #[test]
    fn can_parse_column_with_cast_as() {
        let json = json!({
            "v": 1,
            "tables": {
                "users": {
                    "favourite_int": {
                        "cast_as": "number"
                    }
                }
            }
        });

        let encrypt_config = parse(json);

        let ident = Identifier::new("users", "favourite_int");

        let column = encrypt_config.get(&ident).expect("column exists");

        assert_eq!(column.cast_type, ColumnType::Float);
        assert_eq!(column.name, "favourite_int");
        assert!(column.indexes.is_empty());
    }

    #[test]
    fn can_parse_empty_indexes() {
        let json = json!({
            "v": 1,
            "tables": {
                "users": {
                    "email": {
                        "indexes": {}
                    }
                }
            }
        });

        let encrypt_config = parse(json);

        let ident = Identifier::new("users", "email");

        let column = encrypt_config.get(&ident).expect("column exists");

        assert!(column.indexes.is_empty());
    }

    #[test]
    fn can_parse_ore_index() {
        let json = json!({
            "v": 1,
            "tables": {
                "users": {
                    "email": {
                        "indexes": {
                            "ore": {}
                        }
                    }
                }
            }
        });

        let encrypt_config = parse(json);

        let ident = Identifier::new("users", "email");

        let column = encrypt_config.get(&ident).expect("column exists");

        assert_eq!(column.indexes[0].index_type, IndexType::Ore);
    }

    #[test]
    fn can_parse_unique_index_with_defaults() {
        let json = json!({
            "v": 1,
            "tables": {
                "users": {
                    "email": {
                        "indexes": {
                            "unique": {}
                        }
                    }
                }
            }
        });

        let encrypt_config = parse(json);

        let ident = Identifier::new("users", "email");

        let column = encrypt_config.get(&ident).expect("column exists");

        assert_eq!(
            column.indexes[0].index_type,
            IndexType::Unique {
                token_filters: vec![]
            }
        );
    }

    #[test]
    fn can_parse_unique_index_with_token_filter() {
        let json = json!({
            "v": 1,
            "tables": {
                "users": {
                    "email": {
                        "indexes": {
                            "unique": {
                                "token_filters": [
                                    {
                                        "kind": "downcase"
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        });

        let encrypt_config = parse(json);

        let ident = Identifier::new("users", "email");

        let column = encrypt_config.get(&ident).expect("column exists");

        assert_eq!(
            column.indexes[0].index_type,
            IndexType::Unique {
                token_filters: vec![TokenFilter::Downcase]
            }
        );
    }

    #[test]
    fn can_parse_match_index_with_defaults() {
        let json = json!({
            "v": 1,
            "tables": {
                "users": {
                    "email": {
                        "indexes": {
                            "match": {}
                        }
                    }
                }
            }
        });

        let encrypt_config = parse(json);

        let ident = Identifier::new("users", "email");

        let column = encrypt_config.get(&ident).expect("column exists");

        assert_eq!(
            column.indexes[0].index_type,
            IndexType::Match {
                tokenizer: Tokenizer::Standard,
                token_filters: vec![],
                k: 6,
                m: 2048,
                include_original: false
            }
        );
    }

    #[test]
    fn can_parse_match_index_with_all_opts_set() {
        let json = json!({
            "v": 1,
            "tables": {
                "users": {
                    "email": {
                        "indexes": {
                            "match": {
                                "tokenizer": {
                                    "kind": "ngram",
                                    "token_length": 3,
                                },
                                "token_filters": [
                                    {
                                        "kind": "downcase"
                                    }
                                ],
                                "k": 8,
                                "m": 1024,
                                "include_original": true
                            }
                        }
                    }
                }
            }
        });

        let encrypt_config = parse(json);

        let ident = Identifier::new("users", "email");

        let column = encrypt_config.get(&ident).expect("column exists");

        assert_eq!(
            column.indexes[0].index_type,
            IndexType::Match {
                tokenizer: Tokenizer::Ngram { token_length: 3 },
                token_filters: vec![TokenFilter::Downcase],
                k: 8,
                m: 1024,
                include_original: true
            }
        );
    }

    #[test]
    fn can_parse_ste_vec_index() {
        let json = json!({
            "v": 1,
            "tables": {
                "users": {
                    "event_data": {
                        "cast_as": "json",
                        "indexes": {
                            "ste_vec": {
                                "prefix": "event-data"
                            }
                        }
                    }
                }
            }
        });

        let encrypt_config = parse(json);

        let ident = Identifier::new("users", "event_data");

        let column = encrypt_config.get(&ident).expect("column exists");

        assert_eq!(column.cast_type, ColumnType::JsonB);
        assert_eq!(
            column.indexes[0].index_type,
            IndexType::SteVec {
                prefix: "event-data".into(),
                term_filters: vec![],
                array_index_mode: Default::default(),
            },
        );
    }

    #[test]
    fn ste_vec_with_non_json_cast_as_fails_validation() {
        let json = json!({
            "v": 1,
            "tables": {
                "users": {
                    "event_data": {
                        "cast_as": "string",
                        "indexes": {
                            "ste_vec": {
                                "prefix": "event-data"
                            }
                        }
                    }
                }
            }
        });

        let result = serde_json::from_value::<EncryptConfig>(json)
            .unwrap()
            .into_config_map();

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("users"),
            "Error should mention table name: {}",
            err_msg
        );
        assert!(
            err_msg.contains("event_data"),
            "Error should mention column name: {}",
            err_msg
        );
        assert!(
            err_msg.contains("ste_vec"),
            "Error should mention ste_vec index: {}",
            err_msg
        );
        assert!(
            err_msg.contains("json"),
            "Error should mention json cast_as requirement: {}",
            err_msg
        );
    }

    #[test]
    fn ste_vec_with_json_cast_as_succeeds() {
        let json = json!({
            "v": 1,
            "tables": {
                "users": {
                    "event_data": {
                        "cast_as": "json",
                        "indexes": {
                            "ste_vec": {
                                "prefix": "event-data"
                            }
                        }
                    }
                }
            }
        });

        let result = serde_json::from_value::<EncryptConfig>(json)
            .unwrap()
            .into_config_map();

        assert!(result.is_ok(), "ste_vec with json cast_as should succeed");
        let config = result.unwrap();
        let ident = Identifier::new("users", "event_data");
        let column = config.get(&ident).expect("column exists");
        assert_eq!(column.cast_type, ColumnType::JsonB);
    }
}
