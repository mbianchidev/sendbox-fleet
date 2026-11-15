#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use fleet_server::admin::{self, AdminCommand};
use fleet_server::config::{Config, DATABASE_URL_VAR, DatabaseUrl};
use fleet_server::{logging, server};

/// SendBox shared governance service.
#[derive(Debug, Parser)]
#[command(name = "sendbox-fleet", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve the API (the default).
    Serve,
    /// Bootstrap principals, tokens, and projects directly in the database.
    #[command(subcommand)]
    Admin(AdminCommand),
}

fn main() -> ExitCode {
    match Cli::parse().command {
        None | Some(Command::Serve) => serve(),
        Some(Command::Admin(command)) => run_admin(command),
    }
}

fn run_admin(command: AdminCommand) -> ExitCode {
    let url = match std::env::var(DATABASE_URL_VAR)
        .map_err(|_| format!("{DATABASE_URL_VAR} is required"))
        .and_then(|url| DatabaseUrl::parse(&url).map_err(|error| error.to_string()))
    {
        Ok(url) => url,
        Err(error) => {
            eprintln!("sendbox-fleet: configuration error: {error}");
            return ExitCode::from(2);
        }
    };
    match actix_web::rt::System::new().block_on(admin::run(&url, command)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sendbox-fleet admin: {error}");
            ExitCode::FAILURE
        }
    }
}

fn serve() -> ExitCode {
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
