# Ramflux integration tests

Open headless integration and realnet acceptance tests for Ramflux.

## Durable custody budget slice

`tests::custody_cli_budget::custody_cli_budget_realnet_poll_stop_and_restore`
reads the private durable budget inspection before creating any principals. It
selects one prefix row, records its retained and effective start counts, and
admits exactly `limit - start_count` new principals. The following principal
must receive typed `Capacity` with the exact durable daily reset. Polling and
backup/import do not add admissions. With one remaining slot, only one participant
is used; with no remaining slots, the slice logs the inspected count and a clear
skip without creating any principal. Ambiguous prefixes, count drift, a changed
window, or insufficient global headroom fail instead of consuming extra slots.

Without additional configuration this runs against a disposable Compose fixture.
For an operator node, set `RAMFLUX_CUSTODY_BUDGET_TARGET` to an operator-owned JSON
file with these fields:

- `profile`: a current, explicitly verified SDK `NodeProfile`, with
  `builtin = true`, `pin_source = "builtin"`, and `enabled = true`.
- `prefix`: the exact node-keyed hash of this client's daily prefix row.
- `quota_command`: a nonempty argv array for a private, read-only inspection
  program returning the FU-01 API JSON (`observed_at` and `rows`).
- `metrics_command`: a nonempty argv array for a private, read-only program
  returning router `/perf/metrics` JSON, including `custody`.

The programs run directly, with no shell interpolation. Keep operator tokens in
private environment files used by those programs, not argv or this JSON. The
slice never publishes an admin port or changes an operator node. An invalid
operator target or unavailable inspection fails before account creation; it
never silently substitutes a private Compose node. Provide inspection access to
the running router before starting the acceptance run. An operator node needs
an existing, explicitly selected row; only the fresh private fixture can infer
zero from an empty receipt table and its known default limit.

```sh
RAMFLUX_ITEST_REALNET=1 \
RAMFLUX_CUSTODY_BUDGET_TARGET=/path/to/operator-target.json \
cargo test --locked --features realnet --no-default-features \
  tests::custody_cli_budget::custody_cli_budget_realnet_poll_stop_and_restore \
  -- --exact --nocapture
```

Use the slice's `BUDGET target=operator`, `BUDGET start`, and `BUDGET complete`
lines as acceptance evidence. Each additional principal is spaced by 20 seconds
to avoid mistaking the short-window budget for the daily one. The original
15-minute poll/restore allowance is extended only by that required spacing for
the inspected remainder. `RAMFLUX_CUSTODY_BUDGET_RF_BINARY` can identify an
already built native diagnostic `rf` from the pinned product revision.
