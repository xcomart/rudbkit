# rudbkit

Shared database connection infrastructure for [rudbgen](https://github.com/xcomart/rudbgen)
and [rudbman](https://github.com/xcomart/rudbman). It has no GUI dependency.

| Crate | Responsibility |
| --- | --- |
| `rudbkit-core` | Compatible SSH profile serialization, JDBC URL templates and tunnel redirection, connection validation and ordered profile/secret saving. |
| `rudbkit-ssh` | SSH authentication, host-key verification, local forwarding and a pool whose leases own a specific connection generation. |
| `rudbkit-jdbc` | JVM options, bundled runtime discovery, process-wide startup and JNI calls to an application-supplied bridge class. |

Applications keep their settings, keychain storage, Java bridge protocol and UI.
They supply those through small adapters. `rudbkit-jdbc` accepts a bridge class,
application name and environment override; it locates the selected JVM library
without modifying the process environment. The first successful startup fixes
the runtime configuration for the rest of that process.

Both consumers pin these crates to the same Git revision in their root Cargo
manifests. Cargo fetches the repository automatically; a separate checkout is
only needed when developing the shared code. To test a local checkout, override
all three crates in an uncommitted Cargo patch table:

```toml
[patch."https://github.com/xcomart/rudbkit"]
rudbkit-core = { path = "../rudbkit/crates/rudbkit-core" }
rudbkit-ssh = { path = "../rudbkit/crates/rudbkit-ssh" }
rudbkit-jdbc = { path = "../rudbkit/crates/rudbkit-jdbc" }
```

## Validation

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The SSH suite starts local servers and exercises forwarding, authentication,
host-key checks, disconnects and tunnel ownership. It needs permission to bind
loopback ports, but no external SSH server. The database applications additionally
run their real JVM and H2 integration suites against this shared runtime. Run
those suites before updating their pinned revision.

Connection saving validates before any write, persists the profile, then writes
secrets. A secret-store failure can leave the profile on disk; the application
keeps its form open and retries, and connects only after the current save succeeds.

## License

[MIT](LICENSE).
