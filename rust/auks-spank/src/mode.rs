use std::sync::Mutex;

use crate::{config::PluginConfig, spank::Spank};

/// AUKS plugin operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Do not forward credentials.
    Disabled,
    /// Forward credentials.
    Enabled,
    /// Forward credentials without further renewal.
    Done,
}

/// Last option mode selected by the Slurm option callback.
pub static OPTION_MODE: Mutex<Option<Mode>> = Mutex::new(None);

/// Parses an option value.
pub fn parse_option(value: &str) -> Option<Mode> {
    match value {
        "yes" => Some(Mode::Enabled),
        "no" => Some(Mode::Disabled),
        "done" => Some(Mode::Done),
        _ => None,
    }
}

/// Decides the mode using option, environment, and configuration precedence.
pub fn decide(option: Option<Mode>, env: Option<&str>, default: Mode) -> Mode {
    if let Some(option) = option {
        return option;
    }
    match env {
        Some("yes") => Mode::Enabled,
        Some("done") => Mode::Done,
        Some(_) => Mode::Disabled,
        None => default,
    }
}

/// Decides a mode from a SPANK handle and plugin configuration.
pub fn decide_for_spank(spank: Spank, config: &PluginConfig) -> Mode {
    if let Some(minimum_uid) = config.minimum_uid {
        let uid = if spank.remote() {
            spank.job_uid().ok()
        } else {
            Some(unsafe { libc::geteuid() as u32 })
        };
        if uid.is_some_and(|uid| uid < minimum_uid) {
            return Mode::Disabled;
        }
    }
    let option = OPTION_MODE.lock().ok().and_then(|guard| *guard);
    let env = if spank.remote() {
        spank.getenv("SLURM_SPANK_AUKS")
    } else {
        std::env::var("SLURM_SPANK_AUKS").ok()
    };
    decide(option, env.as_deref(), config.default_mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_precedes_environment() {
        assert_eq!(
            decide(Some(Mode::Disabled), Some("yes"), Mode::Enabled),
            Mode::Disabled
        );
        assert_eq!(decide(None, Some("yes"), Mode::Disabled), Mode::Enabled);
        assert_eq!(
            decide(None, Some("unexpected"), Mode::Enabled),
            Mode::Disabled
        );
        assert_eq!(decide(None, Some("done"), Mode::Disabled), Mode::Done);
        assert_eq!(decide(None, Some("bogus"), Mode::Enabled), Mode::Disabled);
    }
}
