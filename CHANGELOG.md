# Changelog

## 0.2.0

### Breaking

- Removed `Decision{Allow, Deny}`, `PermissionCheck`, `AllowAll`,
  `ReadGrant`, `MessageGrant`, `ManageGrant`, `check_read`, `check_message`,
  `check_manage`, and the unit `Denied`.
- `Identity::new` and `ResourceRef::new` are fallible and return
  `Result<_, EmptyId>`.

### Added

- `Decision<R, A = ()>` with `Deny`, `Ask` and `Allow`, and the combinators
  `strictest` / `most_permissive` / `deny_on_ask` on it.
- `Reason` (ranked reasons) and `Merge` (for `Ask` payloads).
- `strictest_all`, `most_specific` and `with_snapshot` (fail-closed).
- `Verb` and `Policy`, and the owned `Grant<V, P>` minted only by `check`.
- `Grant::still_allowed`, which asks the policy afresh each time.
- `Denied<R>`, which carries the reason and forwards its coded-error facts.
- `testing::AllowWith<P>` behind the `testing` feature (dev-dependencies only).

### Consumer checks

- Gate the `testing` feature: enable it only in `[dev-dependencies]`, never in
  `[dependencies]`, and for each binary check that
  `cargo tree -e normal,features -i access-control` does not show the
  `testing` feature. `AllowWith` can mint a grant for any verb, so a
  production build that reaches it would make every grant forgeable.

### Dependencies

- Depends on coded-error at `ffeaf39` (`ffeaf3949230a8883b56c75e7031346a4f28ed4d`),
  with default features off.
- Note: `coded_error::downcast_ref::<R>()` does not see through `Denied<R>`.
  Callers should call `into_reason()` first and downcast the reason.
