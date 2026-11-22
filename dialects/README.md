# Shipped dialect profiles

Each `<id>.yml` here is a dialect profile rudbman and rudbgen ship, with the
`<id>.groovy` rudbman's bridge needs beside it, if it needs one. They are
compiled into `rudbkit-core` (`dialects::SHIPPED`) and, through it, into
both applications, each of which writes them into its own
`<config>/dialects` at start-up, where a user may change them. The rules are
§12 of rudbman's
[`docs/dialect-profiles.md`](https://github.com/xcomart/rudbman/blob/dev/docs/dialect-profiles.md),
and the format is §4.

| Profile | Product |
| --- | --- |
| `tidb.yml`, `tidb.groovy` | TiDB, on `mysql` |
| `cockroachdb.yml` | CockroachDB, on `postgres` |
| `firebird.yml`, `firebird.groovy` | Firebird 3 and later, on `generic` |

What each rests on, and what its product does not do, is §12.1.

A profile's `driver.icon` names a mark the applications ship (`tidb`,
`mysql`, …) or an image file — PNG, JPEG, WebP, GIF, BMP, ICO or SVG, by an
absolute path or one relative to the profiles' folder, beside the profile.
Each application draws it beside the driver, resampled to its size, and falls
back to the dialect's mark when the file cannot be read (`icon_ref`).

rudbman reads every part of a profile. rudbgen reads its `driver` section and,
of its `bridge` half, what its own bridge answers — `detect`,
`catalog_is_schema` and `comments`; it runs no script.

A script shipped here is allowed to run as it is written (§12): the user is
asked only about a script they have changed. A database product supported
from now on is added here rather than as a built-in in code. rudbkit's tests
read every profile here, and rudbman's load them, so one that does not load
fails the tests; a product is tested against a server of its own in both
applications' container suites.
