# sendbox-fleet

Shared governance service for [SendBox](https://github.com/mbianchidev/sendbox) governed sessions: operator-signed policy profiles shared across users and hosts, project-scoped roles, session admission, credential grant authorization and revocation, expiring exceptions, and central audit. It is increment 2 of [mbianchidev/sendbox#87](https://github.com/mbianchidev/sendbox/issues/87).

> **Status: scaffold.** The server runs, applies its schema, authenticates every `/v1` request, and validates bodies against the shared contract, but every management operation returns `501 Not Implemented`. Provider credentials never reach this service; they stay in the SendBox host broker.

## Quick start

```sh
export FLEET_DATABASE_URL='sqlite://sendbox-fleet.db?mode=rwc'
cargo run --bin sendbox-fleet
curl http://127.0.0.1:8080/readyz
```

With PostgreSQL: `cp .env.example .env`, set `POSTGRES_PASSWORD`, then `docker compose build --no-cache && docker compose up`.

## Documentation

- [Architecture](docs/architecture.md): relationship to SendBox, trust boundaries, API surface, schema
- [Shared contract](docs/contract.md): how `sendbox-governance` is pinned and versioned
- [Threat model](docs/threat-model.md)
- [Roadmap](docs/roadmap.md): increment-2 work mapped to the issue's acceptance criteria
- [Development](docs/development.md): configuration, local runs, tests, logs
- [Contributing](CONTRIBUTING.md) and [security](SECURITY.md)

## License

[Apache-2.0](LICENSE)
