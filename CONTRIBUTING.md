# Contributing to nostrfy

Thanks for your interest in improving nostrfy. This document covers the
licensing terms for contributions and the checks a change is expected to
pass.

## Licensing of contributions

nostrfy is dual-licensed under the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at the user's option.

By submitting a contribution (a pull request, patch, or any other change
intentionally submitted for inclusion in this project), you agree that your
contribution is licensed under both of these licenses, without any
additional terms or conditions — the same "inbound = outbound" rule used by
the Rust project and most of the Rust ecosystem. You retain the copyright to
your contribution; you only grant the project the right to distribute it
under the project's licenses.

If you do not want to grant these terms, please do not submit the change.
If you are contributing on behalf of an employer, make sure you have
permission to do so.

## Before you open a pull request

Run the same checks CI runs, with warnings treated as errors:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

All four must pass without warnings or failures.

## Guidelines

- **NIP conformance is strict.** Changes touching protocol behavior should
  cite the relevant NIP requirement in the code comment or PR description.
- **Fail closed.** Security-relevant state that cannot be read or verified
  must reject or refuse startup, never degrade to empty/permissive
  (see the many `fail-closed` comments for the established pattern).
- **Bound everything.** New in-memory state, queues, and loops reachable
  from unauthenticated input need an explicit cap or eviction policy.
- **Add regression tests.** A bug fix should come with a test that fails
  without the fix; a behavior change with a test that pins the new
  behavior.
- **Document the why.** Comments in this codebase explain *why* a decision
  was made (especially the trade-offs), not what the code does. Follow that
  style.
- **Update the docs.** `docs/CONFIGURATION.md`, `docs/MANUAL.md`, and
  `README.md` track the implementation; keep them in sync when behavior,
  defaults, or the reload matrix change.

## Reporting issues

Please include the relay version (`nostrfy --version`), the configuration
(with secrets redacted), and the relevant log lines. Security issues should
be reported privately rather than in a public issue.
