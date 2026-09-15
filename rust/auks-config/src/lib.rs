//! Parser for the AUKS client configuration file.

use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

use thiserror::Error;

/// A parsed AUKS configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuksConfig {
    /// Client and server settings.
    pub client: ClientConfig,
    /// All parsed blocks, including blocks not used by the client yet.
    pub blocks: BTreeMap<String, BTreeMap<String, String>>,
}

/// Client connection settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfig {
    /// Primary daemon endpoint.
    pub primary: Server,
    /// Optional secondary daemon endpoint.
    pub secondary: Option<Server>,
    /// Optional cross-realm target.
    pub cross_realm: Option<String>,
    /// Whether NAT traversal is enabled.
    pub nat: bool,
    /// Number of connection attempts.
    pub retries: u32,
    /// Connection timeout.
    pub timeout: Duration,
    /// Delay between retries.
    pub delay: Duration,
    /// Optional helper script path.
    pub helper_script: Option<String>,
}

/// A daemon endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// Configured host name.
    pub host: String,
    /// Address used for the connection.
    pub address: String,
    /// TCP port.
    pub port: String,
    /// Kerberos service principal.
    pub principal: String,
}

/// Configuration parsing failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    /// The configuration syntax is invalid.
    #[error("configuration syntax error at byte {offset}: {message}")]
    Syntax {
        /// Byte offset where parsing failed.
        offset: usize,
        /// Description of the syntax error.
        message: String,
    },
    /// A numeric value is invalid.
    #[error("invalid {field}: {value}")]
    InvalidNumber {
        /// Configuration field name.
        field: &'static str,
        /// Invalid field value.
        value: String,
    },
    /// The file could not be read.
    #[error("unable to read configuration: {0}")]
    Io(String),
}

/// Parses an AUKS configuration file.
pub fn parse_file(path: impl AsRef<std::path::Path>) -> Result<AuksConfig, ConfigError> {
    let contents = fs::read_to_string(path).map_err(|error| ConfigError::Io(error.to_string()))?;
    parse_str(&contents)
}

/// Parses an AUKS configuration string.
pub fn parse_str(input: &str) -> Result<AuksConfig, ConfigError> {
    let blocks = Parser::new(input).parse()?;
    let common = blocks.get("common").cloned().unwrap_or_default();
    let api = blocks.get("api").cloned().unwrap_or_default();
    let primary = server(&common, "Primary", false);
    let secondary = common
        .contains_key("SecondaryHost")
        .then(|| server(&common, "Secondary", true));
    let cross_realm = common
        .get("CrossRealm")
        .filter(|value| !value.is_empty())
        .cloned();
    let nat = common
        .get("NAT")
        .is_some_and(|value| value.eq_ignore_ascii_case("yes"));
    let retries = number(&common, "Retries", 3)?;
    let timeout = number(&common, "Timeout", 10)?;
    let delay = number(&common, "Delay", 10)?;
    let helper_script = api
        .get("HelperScript")
        .filter(|value| !value.is_empty())
        .cloned();
    Ok(AuksConfig {
        client: ClientConfig {
            primary,
            secondary,
            cross_realm,
            nat,
            retries,
            timeout: Duration::from_secs(timeout.into()),
            delay: Duration::from_secs(delay.into()),
            helper_script,
        },
        blocks,
    })
}

fn server(values: &BTreeMap<String, String>, prefix: &str, optional: bool) -> Server {
    let host = values
        .get(&format!("{prefix}Host"))
        .cloned()
        .unwrap_or_else(|| {
            if optional {
                String::new()
            } else {
                "localhost".into()
            }
        });
    let address = values
        .get(&format!("{prefix}Address"))
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| host.clone());
    Server {
        host,
        address,
        port: values
            .get(&format!("{prefix}Port"))
            .cloned()
            .unwrap_or_else(|| "12345".into()),
        principal: values
            .get(&format!("{prefix}Principal"))
            .cloned()
            .unwrap_or_default(),
    }
}

fn number(
    values: &BTreeMap<String, String>,
    key: &'static str,
    default: u64,
) -> Result<u32, ConfigError> {
    values.get(key).map_or(Ok(default as u32), |value| {
        value
            .parse::<u32>()
            .map_err(|_| ConfigError::InvalidNumber {
                field: key,
                value: value.clone(),
            })
    })
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            pos: 0,
        }
    }

    fn parse(mut self) -> Result<BTreeMap<String, BTreeMap<String, String>>, ConfigError> {
        let mut blocks = BTreeMap::new();
        while self.skip_space_and_comments() {
            let name = self.identifier()?;
            self.expect(b'{')?;
            let mut values = BTreeMap::new();
            loop {
                self.skip_space_and_comments();
                if self.consume(b'}') {
                    break;
                }
                let key = self.identifier()?;
                self.expect(b'=')?;
                let value = self.value()?;
                self.expect(b';')?;
                values.insert(key, value);
            }
            blocks.insert(name, values);
        }
        Ok(blocks)
    }

    fn skip_space_and_comments(&mut self) -> bool {
        loop {
            while self
                .input
                .get(self.pos)
                .is_some_and(u8::is_ascii_whitespace)
            {
                self.pos += 1;
            }
            if self.input.get(self.pos) == Some(&b'#') {
                while self.pos < self.input.len() && self.input[self.pos] != b'\n' {
                    self.pos += 1;
                }
                continue;
            }
            return self.pos < self.input.len();
        }
    }

    fn identifier(&mut self) -> Result<String, ConfigError> {
        let start = self.pos;
        while self
            .input
            .get(self.pos)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || b"_.-:".contains(byte))
        {
            self.pos += 1;
        }
        if start == self.pos {
            return Err(self.error("expected identifier"));
        }
        Ok(String::from_utf8_lossy(&self.input[start..self.pos]).into_owned())
    }

    fn value(&mut self) -> Result<String, ConfigError> {
        self.skip_space_and_comments();
        if let Some(quote @ (b'"' | b'\'')) = self.input.get(self.pos).copied() {
            self.pos += 1;
            let mut output = Vec::new();
            while let Some(&byte) = self.input.get(self.pos) {
                self.pos += 1;
                if byte == quote {
                    return Ok(String::from_utf8_lossy(&output).into_owned());
                }
                if byte == b'\\' {
                    if let Some(&escaped) = self.input.get(self.pos) {
                        self.pos += 1;
                        output.push(escaped);
                    } else {
                        return Err(self.error("unterminated escape"));
                    }
                } else {
                    output.push(byte);
                }
            }
            return Err(self.error("missing closing quote"));
        }
        let start = self.pos;
        while self
            .input
            .get(self.pos)
            .is_some_and(|byte| !byte.is_ascii_whitespace() && *byte != b';')
        {
            self.pos += 1;
        }
        if start == self.pos {
            return Err(self.error("expected value"));
        }
        Ok(String::from_utf8_lossy(&self.input[start..self.pos]).into_owned())
    }

    fn expect(&mut self, byte: u8) -> Result<(), ConfigError> {
        self.skip_space_and_comments();
        if self.consume(byte) {
            Ok(())
        } else {
            Err(self.error(&format!("expected '{}'", byte as char)))
        }
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.input.get(self.pos) == Some(&byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn error(&self, message: &str) -> ConfigError {
        ConfigError::Syntax {
            offset: self.pos,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixture() {
        let config = parse_file("../../fixtures/auks.conf").expect("fixture");
        assert_eq!(config.client.primary.host, "auks");
        assert_eq!(config.client.primary.address, "auks");
        assert_eq!(config.client.primary.port, "12345");
        assert_eq!(
            config.client.primary.principal,
            "auks/auks.example.com@EXAMPLE.COM"
        );
        assert_eq!(
            config.client.secondary,
            Some(Server {
                host: "auks2".into(),
                address: "auks2".into(),
                port: "12345".into(),
                principal: "host/auks2.myrealm.org@MYREALM.ORG".into(),
            })
        );
        assert_eq!(config.client.cross_realm, None);
        assert!(!config.client.nat);
        assert_eq!(config.client.retries, 3);
        assert_eq!(config.client.timeout, Duration::from_secs(10));
        assert_eq!(config.client.delay, Duration::from_secs(3));
        assert_eq!(
            config.client.helper_script.as_deref(),
            Some("/usr/local/bin/renewer_script.sh")
        );
        assert!(config.blocks.contains_key("auksd"));
        assert!(config.blocks.contains_key("renewer"));
    }

    #[test]
    fn applies_minimal_defaults() {
        let config = parse_str("common { PrimaryHost = node; }").expect("config");
        assert_eq!(config.client.primary.address, "node");
        assert_eq!(config.client.primary.port, "12345");
        assert_eq!(config.client.primary.principal, "");
        assert_eq!(config.client.secondary, None);
        assert_eq!(config.client.retries, 3);
        assert_eq!(config.client.timeout, Duration::from_secs(10));
        assert_eq!(config.client.delay, Duration::from_secs(10));
        assert!(!config.client.nat);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_str("not a config").is_err());
    }
}
