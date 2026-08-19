# Contributing

## Development

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

CI runs the same gates on Linux, macOS, and Windows; pull requests need a
green run.

## Commit style

Use Conventional Commits, with a scope where one fits:

```
fix(core): redact sensitive fields by key suffix
feat(diff): add --strict-ids flag
docs: describe the replay ordering model
```

Types in use: `feat`, `fix`, `docs`, `test`, `refactor`, `ci`, `chore`.
Commits are authored by the person who ships them — no AI co-author or
attribution trailers.

## Releases

1. Bump `version` in `Cargo.toml` on `main` through a pull request.
2. Tag the release commit `v<version>` and push the tag. The release
   workflow verifies the tag matches the crate version, runs the full test
   suite, attaches binaries for Linux, macOS, and Windows to a GitHub
   release, and publishes to crates.io via
   [trusted publishing](https://crates.io/docs/trusted-publishing).

crates.io requires the first version of a crate to be published manually
(`cargo publish` with a local token). The workflow skips versions that are
already on crates.io, so the tag can still be pushed after a manual publish
to produce the GitHub release and binaries.
