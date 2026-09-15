//! Minimal command-line client for the AUKS daemon.

use std::env;
use std::process::ExitCode;

use auks_client::Client;
use auks_config::parse_file;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let mut config_path = "/conf/auks.conf".to_owned();
    let mut operation = None;
    while let Some(arg) = args.next() {
        if arg == "-c" {
            config_path = args.next().unwrap_or_else(|| "/conf/auks.conf".into());
        } else {
            operation = Some((arg, args.next()));
            break;
        }
    }
    let Some((operation, value)) = operation else {
        eprintln!("usage: auksctl-rs [-c FILE] ping|add [CCACHE]|get UID|remove UID");
        return ExitCode::from(2);
    };
    let config = match parse_file(config_path) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let client = Client::new(config.client);
    let result = match operation.as_str() {
        "ping" => client.ping().map(|_| ()),
        "add" => client.add_cred(value.as_deref()),
        "get" => {
            let Some(uid) = value.and_then(|uid| uid.parse().ok()) else {
                eprintln!("get requires a numeric UID");
                return ExitCode::from(2);
            };
            client.get_cred(uid).map(|cred| {
                println!(
                    "principal={} uid={} start={} end={} renew_till={}",
                    cred.info.principal,
                    cred.info.uid,
                    cred.info.starttime,
                    cred.info.endtime,
                    cred.info.renew_till
                );
            })
        }
        "remove" => {
            let Some(uid) = value.and_then(|uid| uid.parse().ok()) else {
                eprintln!("remove requires a numeric UID");
                return ExitCode::from(2);
            };
            client.remove_cred(uid)
        }
        _ => {
            eprintln!("unknown operation");
            return ExitCode::from(2);
        }
    };
    if let Err(error) = result {
        eprintln!("{error}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
