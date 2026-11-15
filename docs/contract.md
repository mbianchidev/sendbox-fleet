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
sendbox-governance = { git = "https://github.com/mbianchidev/sendbox", rev = "bd7498ab24c3c9cfd98f80349bee31fed667539b" }
```

- The dependency is pinned to an exact commit, and `Cargo.lock` records it, so
  every build sees the same contract. A contract change is always a deliberate
  pin update in a reviewed pull request.
- `sendbox-governance` inherits versions from the sendbox workspace and
  depends on `sendbox-core` by path; Cargo resolves both from the same git
  checkout.
- The pinned commit is on the increment-1 branch
  `cp-desktop-governed-sessions-policy-profiles`. Once that work merges, move
  the pin to the merged commit on `main` (or a tag) so the revision cannot
  disappear if the branch is rewritten or deleted.

To update the pin:

```sh
# edit `rev` in Cargo.toml, then
cargo update -p sendbox-governance
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
