# Contributing to rudbkit

rudbkit is the shared database connection infrastructure used by rudbgen and
rudbman. Contributions should keep it independent of either application's UI,
settings format, secret-store implementation and Java bridge protocol. Start
with the [README](README.md) for the boundaries between the three crates.

## Reporting a problem or proposing a change

Search the [issues](https://github.com/xcomart/rudbkit/issues) first. Include the
rudbkit revision, affected consumer and version, OS, reproduction steps, and
expected and actual behavior. For JVM issues, include the JDK vendor/version
and selected runtime; for SSH issues, describe authentication and forwarding
without including passwords, private keys or private host details.

Discuss public API changes together with their effect on both consumers before
implementing them. A small reproduction at the shared-library boundary is
especially useful.

## Development environment

Use Git, stable Rust, `rustfmt`, `clippy` and a native compiler toolchain. The
workspace uses edition 2024. There is no GUI dependency, no Java bridge to build
here, and no application binary to launch.

From a checkout of `dev`:

```sh
rustup component add rustfmt clippy
cargo build --workspace --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Also check public API documentation, as the Linux CI job does. In a POSIX shell:

```sh
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked
```

In PowerShell, set `$env:RUSTDOCFLAGS = '-D warnings'` before the `cargo doc`
command. See [CI](.github/workflows/ci.yml) for the current platform matrix.

## Where changes belong

| Crate | Responsibility |
| --- | --- |
| `rudbkit-core` | SSH profile serialization, JDBC URL templates and redirection, connection validation and ordered profile/secret saving |
| `rudbkit-ssh` | Authentication, host-key verification, forwarding and generation-owned tunnel leases |
| `rudbkit-jdbc` | Runtime discovery, JVM configuration/startup and JNI access to an application-supplied bridge class |

Applications supply their settings, keychain and bridge adapters. Avoid adding
an application identity or protocol to the shared layer. Preserve these
contracts when changing behavior:

- Existing SSH profiles remain readable and retain their serialized meaning.
- Connection saving validates before writes, persists the profile, then writes
  secrets. A secret-store failure may leave the profile saved; callers must be
  able to retry and must not connect before the current save succeeds.
- A tunnel lease owns its connection generation; releasing an old lease must
  not close a replacement connection.
- Host-key verification and loopback-only local forwarding stay intact.
- The first successful JVM startup fixes that process's runtime configuration.
  Runtime discovery does not mutate the process environment.
- Keep the russh `ring` backend and disabled default features used by the
  workspace, so consumers do not acquire extra Windows build requirements.

## Tests and consumer validation

Start with the crate you changed:

```sh
cargo test -p rudbkit-core --locked
cargo test -p rudbkit-ssh --locked
cargo test -p rudbkit-jdbc --locked
```

The normal SSH tests start their own servers and need permission to bind
loopback ports, not an external SSH account. The real-bastion test is ignored;
read the setup in
[`crates/rudbkit-ssh/tests/e2e.rs`](crates/rudbkit-ssh/tests/e2e.rs) before
running it. Its environment variables use the `RUDBKIT_SSH_TEST_*` prefix.

Shared-library tests alone do not validate the consumers' Java protocols or
their real JVM/H2 integrations. Check both applications before updating their
pinned revision, especially for JVM startup, saving or tunnel-lifetime changes.

Place the three repositories next to one another. In each application's
uncommitted `.cargo/config.toml`, add:

```toml
[patch."https://github.com/xcomart/rudbkit"]
rudbkit-core = { path = "../rudbkit/crates/rudbkit-core" }
rudbkit-ssh = { path = "../rudbkit/crates/rudbkit-ssh" }
rudbkit-jdbc = { path = "../rudbkit/crates/rudbkit-jdbc" }
```

Merge this table into existing local configuration; do not overwrite unrelated
settings. A path override changes dependency resolution, so first let Cargo
update the application's local lockfile without `--locked`:

```sh
# In rudbgen, after building its bridge:
cargo check --workspace
cargo test --workspace --locked

# Repeat in rudbman, after building its bridge:
cargo check --workspace
cargo test --workspace --locked
```

Both consumers need JDK 17+ and their own bridge built with
`./gradlew build --no-daemon` inside `bridge` (`.\gradlew.bat` on Windows).
Follow their full setup and validation guides:
[rudbgen](https://github.com/xcomart/rudbgen/blob/dev/CONTRIBUTING.md) and
[rudbman](https://github.com/xcomart/rudbman/blob/dev/CONTRIBUTING.md).

Keep local patches and path-resolved lockfile changes out of submissions. When
adopting a published change, remove the temporary overrides, update all three
rudbkit entries in each consumer's root manifest to the same Git commit,
regenerate its lockfile and rerun its checks. Include intentional manifest and
lockfile changes together in that consumer's contribution.

## Submit your contribution

Use `cargo fmt --all`, follow the surrounding style, document public APIs and
add focused regression coverage for changed behavior. Changes to public
contracts should explain how existing consumers keep working.

`dev` is the integration branch. Fork if needed, branch from the latest upstream
`dev`, and open a focused pull request targeting `dev`. Maintainers working
directly in this workspace validate and commit on `dev`, then push to
`origin/dev`.

Use `type: summary` for new commit subjects, with a concise imperative summary.
Choose `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `build`, `ci` or `chore`
to describe the change, for example `fix: preserve tunnel lease ownership`
or `docs: add contribution guide`. Release and merge commits also use a prefix,
such as `chore: release <version>` or `chore: merge dev into main`. This convention
applies across all five repositories; do not rewrite existing history to rename
older commits.

In the pull request, explain the problem, behavior change and compatibility
impact. List library checks and consumer checks separately, including anything
not run. Exclude credentials, build artifacts and temporary path overrides.
CI runs on pull requests and pushes to both `dev` and `main`.

Routine work ends at `origin/dev`. Promotion to `main` and release tagging are
separate maintainer actions: merge the `dev` → `main` PR after required checks,
fetch `origin/main`, and tag its verified latest commit. Do not move an existing
release tag.

Contributions are covered by the [MIT license](LICENSE). Preserve third-party
notices when incorporating external code.
