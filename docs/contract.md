# Shared contract

SendBox hosts and this service must agree byte-for-byte on identities,
profile references, session bindings, grants, request contexts, and
decisions. That agreement lives in one crate, `sendbox-governance`, in the
[sendbox](https://github.com/mbianchidev/sendbox) repository
(`crates/sendbox-governance`). This service depends on it instead of
redefining any of those types.

## How it is pinned

```toml
# Cargo.toml (workspace)
sendbox-governance = { git = "https://github.com/mbianchidev/sendbox", branch = "main" }
```

- The dependency tracks sendbox `main`, and `Cargo.lock` records the exact
  commit. CI builds with `--locked`, so every build sees the same contract
  until the lockfile moves.
- [Dependabot](../.github/dependabot.yml) checks sendbox `main` daily and opens
  a pull request that moves `Cargo.lock` to the latest commit. The
  [auto-merge workflow](../.github/workflows/dependabot-auto-merge.yml) enables
  auto-merge on those pull requests, and branch protection merges them only
  after every CI job passes. A contract change that breaks this service leaves
  the pull request open with failing checks for a maintainer to fix.
- `sendbox-governance` inherits versions from the sendbox workspace and
  depends on `sendbox-core` by path; Cargo resolves both from the same git
  checkout.
- Only `main` is tracked, so the recorded commit cannot disappear when sendbox
  feature branches are rewritten or deleted.

To move the lockfile by hand, to the latest `main` commit or to a specific one:

```sh
cargo update -p sendbox-governance
cargo update -p sendbox-governance --precise <commit-sha>
cargo test --locked --workspace
```

## What the API reuses

| Contract type | Used by |
| --- | --- |
| `GovernanceBinding`, `AuthorityRef`, `SessionRef` | `POST /v1/sessions:admit` body |
| `GrantRequest`, `CredentialGrant` | `POST /v1/grants` body and response |
| `GrantId` | `:renew` and `:revoke` path parameter; renew response is a `CredentialGrant` |
| `RevocationReason` | `:revoke` body |
| `RequestContext`, `Decision`, `DenyReason` | `POST /v1/authorize` body and response |
| `ProfileId`, `ProfileRef`, `GovernanceProfile` | `/v1/profiles/{profile_id}`; publication bodies are parsed with `GovernanceProfile::parse` |
| `ProjectId`, `PrincipalId` | Role, exception, and audit endpoints |
| `Sha256Digest` | Digests in responses and audit events |

Validation is the contract's own: identifier grammars, `deny_unknown_fields`,
`GovernanceBinding::validate`, `validate_method`, `validate_path_prefix`, and
`GovernanceProfile::parse`. Invalid input is a `400` problem.

Types that only exist on the management API live in this repository, in the
route module that uses them: `SessionAdmissionRequest`, `RevokeGrantRequest`,
`ProfilePublication` and `ProfileSignature`, `ProjectRole` and `RoleBinding`,
`ExceptionRequest`, and the audit query and event types. The profile signature
envelope is a placeholder: once increment 1 defines the operator signing
format in `sendbox-governance`, the fleet adopts that type instead.

## Versioning

- `sendbox_governance::CONTRACT_VERSION` (currently `1`) is the wire and digest
  version. `GovernanceBinding` and `CredentialGrant` carry it, and validation
  rejects any other value. The server logs it at startup.
- Contract structs use `deny_unknown_fields`, so adding a field is a breaking
  change for older peers. Any change to a contract type or to how digests are
  computed requires bumping `CONTRACT_VERSION` in the sendbox repository and
  then updating this pin; hosts and the fleet must be upgraded together or
  support both versions during the transition.
- The `/v1` path prefix versions the HTTP API surface (routes, fleet-only
  types, problem format). It changes independently of `CONTRACT_VERSION`.
