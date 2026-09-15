use super::mode::Mode;

/// Parsed plugstack configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginConfig {
    /// AUKS synchronization mode.
    pub sync: Option<String>,
    /// Default AUKS mode.
    pub default_mode: Mode,
    /// Whether stack credential publication is enabled.
    pub spankstackcred: bool,
    /// Whether failures are enforced.
    pub enforced: bool,
    /// Whether FILE ccaches are forced.
    pub force_file_ccache: bool,
    /// Whether ccache switching is disabled.
    pub no_cc_switch: bool,
    /// Minimum UID allowed to use AUKS.
    pub minimum_uid: Option<u32>,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            sync: None,
            default_mode: Mode::Disabled,
            spankstackcred: false,
            enforced: false,
            force_file_ccache: false,
            no_cc_switch: false,
            minimum_uid: None,
        }
    }
}

/// Parses plugstack arguments and returns unrecognized arguments separately.
pub fn parse(args: &[String]) -> (PluginConfig, Vec<String>) {
    let mut config = PluginConfig::default();
    let mut unknown = Vec::new();
    for argument in args {
        if let Some(value) = argument.strip_prefix("sync=") {
            config.sync = Some(value.to_owned());
        } else if let Some(value) = argument.strip_prefix("default=") {
            config.default_mode = match value {
                "enabled" => Mode::Enabled,
                "disabled" => Mode::Disabled,
                _ => {
                    unknown.push(argument.clone());
                    config.default_mode
                }
            };
        } else if argument == "spankstackcred=yes" {
            config.spankstackcred = true;
        } else if argument == "enforced" {
            config.enforced = true;
        } else if argument == "force_file_ccache" {
            config.force_file_ccache = true;
        } else if argument == "no_cc_switch" {
            config.no_cc_switch = true;
        } else if let Some(value) = argument.strip_prefix("minimum_uid=") {
            if let Ok(value) = value.parse() {
                config.minimum_uid = Some(value);
            } else {
                unknown.push(argument.clone());
            }
        } else if argument.starts_with("conf=") {
        } else {
            unknown.push(argument.clone());
        }
    }
    (config, unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_arguments_and_reports_unknown() {
        let args = [
            "conf=/conf/auks.conf",
            "default=enabled",
            "sync=wait",
            "enforced",
            "minimum_uid=1000",
            "hostcredcache=/tmp/cc",
            "bogus",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let (config, unknown) = parse(&args);
        assert_eq!(config.default_mode, Mode::Enabled);
        assert_eq!(config.sync.as_deref(), Some("wait"));
        assert_eq!(config.minimum_uid, Some(1000));
        assert_eq!(unknown, ["hostcredcache=/tmp/cc", "bogus"]);
    }
}
