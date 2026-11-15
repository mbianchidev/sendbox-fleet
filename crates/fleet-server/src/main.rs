#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use fleet_server::admin::{self, AdminCommand, AuditCommand};
use fleet_server::config::{Config, DATABASE_URL_VAR, DatabaseUrl, MIGRATE_VAR, parse_migrate};
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
    let report = |result: Result<(), admin::AdminError>| match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sendbox-fleet admin: {error}");
            ExitCode::FAILURE
        }
    };
    if let AdminCommand::Audit(AuditCommand::Keygen { output }) = &command {
        return report(admin::keygen(output));
    }
    let settings = std::env::var(DATABASE_URL_VAR)
        .map_err(|_| format!("{DATABASE_URL_VAR} is required"))
        .and_then(|url| DatabaseUrl::parse(&url).map_err(|error| error.to_string()))
        .and_then(|url| {
            let migrate = std::env::var(MIGRATE_VAR).ok();
            parse_migrate(migrate.as_deref())
                .map(|migrate| (url, migrate))
                .map_err(|error| error.to_string())
        });
    let (url, migrate) = match settings {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("sendbox-fleet: configuration error: {error}");
            return ExitCode::from(2);
        }
    };
    report(actix_web::rt::System::new().block_on(admin::run(&url, migrate, command)))
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
