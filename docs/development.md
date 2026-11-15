# Development

## Prerequisites

- [rustup](https://rustup.rs). The pinned toolchain (Rust 1.93.1 with clippy
  and rustfmt) installs automatically from `rust-toolchain.toml`.
- A Docker-compatible engine with Compose, only for the PostgreSQL stack.

## Configuration

The server reads its configuration from the environment at startup and exits
with status `2` and a message naming the variable when a value is invalid.

| Variable | Default | Meaning |
| --- | --- | --- |
| `FLEET_DATABASE_URL` | required | `sqlite://path.db?mode=rwc`, `sqlite::memory:`, or `postgres://user:password@host:5432/db` |
| `FLEET_BIND` | `127.0.0.1:8080` | Listen address |
| `FLEET_LOG_DIR` | `./logs` | Log directory; relative paths resolve against the working directory at startup |
| `FLEET_LOG_LEVEL` | `info,sqlx=warn` | [`EnvFilter`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html) directives |
| `FLEET_LOG_RETENTION_DAYS` | `30` | Days to keep rotated log files (1 to 3650) |

Database credentials in `FLEET_DATABASE_URL` are never logged.

## Run locally with SQLite

```sh
export FLEET_DATABASE_URL='sqlite://sendbox-fleet.db?mode=rwc'
cargo run --bin sendbox-fleet

curl -i http://127.0.0.1:8080/healthz
curl -i http://127.0.0.1:8080/readyz
curl -i -X POST http://127.0.0.1:8080/v1/authorize   # 401: authentication required
```

Migrations run at startup. Stop the server with Ctrl-C (or `SIGTERM`); it
stops accepting connections, gives in-flight requests up to 30 seconds,
closes the database pool, and flushes logs.

## Run with PostgreSQL (Compose)

```sh
cp .env.example .env        # set POSTGRES_PASSWORD (URL-safe characters)
docker compose build --no-cache && docker compose up
```

The server listens on `127.0.0.1:${FLEET_PORT:-8080}`. The container runs as
an unprivileged user with a read-only root filesystem; logs go to the
`fleet-logs` volume. `docker compose down` stops the stack and keeps data;
`docker compose down --volumes` also deletes the database and logs.

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo audit --deny warnings          # needs cargo-audit; see .cargo/audit.toml
```

Tests use in-memory SQLite and synthetic data. To run the migration tests
against PostgreSQL, point `FLEET_TEST_DATABASE_URL` at a disposable database
whose name ends in `_test` (the tests drop and recreate its `public` schema):

```sh
docker run -d --name sendbox-fleet-pg-test -p 127.0.0.1:55432:5432 \
  -e POSTGRES_DB=sendbox_fleet_test -e POSTGRES_USER=sendbox_fleet \
  -e POSTGRES_HOST_AUTH_METHOD=trust postgres:18.7-alpine3.24
FLEET_TEST_DATABASE_URL=postgres://sendbox_fleet@127.0.0.1:55432/sendbox_fleet_test \
  cargo test --locked --workspace --test migrations -- --test-threads=1
docker rm -f sendbox-fleet-pg-test
```

CI runs formatting, Clippy, and tests on SQLite; the migration tests plus a
start, probe, and graceful-stop run of the server on PostgreSQL; and
`cargo audit`.

## Logs

- Every event is a JSON line written to stdout and to
  `FLEET_LOG_DIR/sendbox-fleet.YYYY-MM-DD.log`. The live file is the one for
  the current UTC date; a new file starts at each UTC midnight.
- Retention runs at startup and then hourly. It deletes only regular files
  named `sendbox-fleet.YYYY-MM-DD.log` whose UTC day ended at least
  `FLEET_LOG_RETENTION_DAYS` days ago, judged by the date in the name rather
  than the modification time. Other files, directories, and symlinks are left
  alone; deletion failures are logged and retried at the next run.
- The log directory is created with mode `0700`.
- File writes go through a bounded queue of 16,384 events. When it is full,
  logging callers wait instead of dropping events.
- Never logged: request bodies, headers (including `Authorization`), query
  strings, and database credentials.
- Rotation is daily only; size-based rotation is a roadmap item.

## Migrations

Schema changes need a new, numbered file in **both** `migrations/postgres` and
`migrations/sqlite` with equivalent constraints. Never edit a migration that
has been applied anywhere: sqlx records checksums and refuses to start on a
mismatch. Add a test in `crates/fleet-server/tests/migrations.rs` for any new
invariant.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `configuration error: FLEET_DATABASE_URL is required` (exit 2) | Export a database URL |
| `cannot connect to postgres://***@...` | Database not reachable or wrong credentials |
| `cannot listen on ...` | Port already in use; set `FLEET_BIND` or `FLEET_PORT` |
| `cannot create log directory` | `FLEET_LOG_DIR` not writable by the server user |
| Every `/v1` call returns `401 authentication provider not configured` | Expected: no identity provider is integrated yet |
