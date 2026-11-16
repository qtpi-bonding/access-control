# access-control

Typed allow/deny/ask decisions with ranked reasons, and grants that only a
successful `check` can mint. The crate is synchronous, has no async runtime,
no store, and depends only on `coded-error`.

## Scope

The crate provides three things:

- **Decisions.** `Decision<R, A = ()>` is `Deny(R)`, `Ask(A)` or `Allow`.
  Reasons implement `Reason` and carry a rank: when two denials meet, the
  higher rank wins regardless of order, and an equal rank keeps the first.
  `Merge` combines `Ask` payloads. The combinators are `strictest_all`,
  `most_specific` and `with_snapshot`, and `Decision::deny_on_ask` settles an
  `Ask` explicitly. `with_snapshot` is fail-closed: a missing snapshot denies
  without calling the closure.
- **Identifiers.** `Identity` and `ResourceRef` are opaque and never empty.
  `new` returns `Result<_, EmptyId>`.
- **Grants.** `Grant<V, P>` is an owned proof that a `Policy<V>` allowed a
  caller to perform the verb `V` on a resource. It has no public constructor
  and no `Default`: outside `check` it is unforgeable, but any `Policy` in
  scope that is implemented for `V` can mint one through `check`, and
  `testing::AllowWith` can mint a grant for any `V` when the `testing`
  feature is enabled. Keep your `Verb` types `pub(crate)` so that only your
  own policy can implement `Policy` for them. `Grant` is `Clone`, `Send`,
  `Sync` and `'static`. `Grant::still_allowed` asks the policy again on each
  call and caches nothing. Refusals are `Denied<R>`, which forwards the
  reason's `coded-error` facts unchanged.

Consumers declare their own `Verb` types and implement `Policy` over their
own rules and facts. The crate ships no verbs and no policy of its own.

Known consumers:

- **grorg** uses `Decision`, `Reason`, `strictest_all`, `deny_on_ask` and
  `with_snapshot`. It does not use `Verb` or `Policy`.
- **multimatrix** uses `check`, `Policy`, `Grant` and `Denied` with its
  own verbs and reasons.
- **structmux** does not depend on this crate yet. It may adopt it later,
  using `Decision<&'static str, P>` with a `Merge` impl for its own payload.

### The `testing` feature

`testing::AllowWith<P>` allows every caller, resource and verb. It is for
tests only. Enable the `testing` feature only in `[dev-dependencies]`, never
in `[dependencies]`, so production builds cannot mint grants with it.
Gate on it: for each binary, `cargo tree -e normal,features -i access-control`
must not show the `testing` feature. Since `AllowWith` can mint a grant for
any verb, a production build that reaches it would make every grant forgeable.

```toml
[dev-dependencies]
access-control = { path = "...", features = ["testing"] }
```

## Example

```rust
use access_control::{check, Decision, Identity, Policy, ResourceRef, Verb};

struct Read;
impl Verb for Read {
    const NAME: &'static str = "read";
}

struct Open;
impl Policy<Read> for Open {
    type Reason = &'static str;
    type Payload = ();
    fn decide(&self, _: &Identity, _: &ResourceRef) -> Decision<&'static str> {
        Decision::Allow
    }
    fn ask_reason(&self) -> &'static str { "asked" }
    fn payload(&self, _: &Identity, _: &ResourceRef) -> Result<(), &'static str> {
        Ok(())
    }
}

let grant = check::<Read, _>(&Open, &Identity::new("agent-123")?, &ResourceRef::new("res:general")?)?;
// only now can a function that requires `&Grant<Read, ()>` be called
```

## Status

Version 0.2.0. This release breaks 0.1.x: the old `Decision{Allow, Deny}`,
`PermissionCheck`, `AllowAll`, the per-verb grant types and the `check_read`,
`check_message` and `check_manage` functions are removed, and `Identity::new`
and `ResourceRef::new` are fallible. See `CHANGELOG.md` for the full list.

The crate depends on `coded-error` at revision `ffeaf39`. Not yet published
(`publish = false`).
