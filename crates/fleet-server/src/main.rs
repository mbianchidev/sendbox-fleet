#![forbid(unsafe_code)]

use std::process::ExitCode;

use fleet_server::config::Config;
use fleet_server::{logging, server};

fn main() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("sendbox-fleet: configuration error: {error}");
            return ExitCode::from(2);
        }
    };
    let logging = match logging::init(&config.logging) {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("sendbox-fleet: cannot start logging: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = actix_web::rt::System::new().block_on(server::run(config, logging.dir.clone()));
    let code = match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "sendbox-fleet failed");
            ExitCode::FAILURE
        }
    };
    drop(logging);
    code
}
