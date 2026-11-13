# access-control

A structurally-enforced read-authorization seam for grorg and multimatrix
— the only two network-reachable stateful services in the concordium
stack (gait and archegraph are pure worker/consumer nodes with no data
of their own to gate, so they never need this crate).

## Scope

This crate defines its own opaque `Identity` and `ResourceRef` types —
not multimatrix's `MessageId`/`AuthoredMessage` or grorg's `ActionId` —
so it has no proto/schema dependency on either repo. Callers wrap their
own identifiers into these types at the point they need a decision.

The property this crate exists to provide: `ReadGrant` has no public
constructor, no `Default`, and is not `Clone`. The only way to obtain
one is calling `check_read` and having it succeed. A function that
returns protected data can require `&ReadGrant` as a parameter, making
it a compile error — not a code-review miss — to fetch protected data
without having gone through the permission check.

The same holds for the other two verbs: `MessageGrant` (sending to a
resource) comes only from `check_message`, and `ManageGrant` (changing a
room's members, managers, closed state or history setting) comes only
from `check_manage`. `PermissionCheck` has `authorize_read`,
`authorize_message` and `authorize_manage`; the last two default to
`Deny`, so a read-only policy fails closed. All three checks return the
same `Denied`. Scope (one room, or `any`) is the policy's business; the
crate is synchronous and stores nothing. Assign, create and oversee are
decided in the embedding service's own policy, not here.

```rust
use access_control::{check_read, AllowAll, Identity, ResourceRef};

let policy = AllowAll;
let caller = Identity::new("agent-123");
let resource = ResourceRef::new("room:general");

let grant = check_read(&policy, &caller, &resource)?;
// only now can a data-returning function that requires `&ReadGrant` be called
```

## Status

There is no authorization policy anywhere in the concordium stack today
— grorg has authentication only, zero authorization. The only shipped
`PermissionCheck` is `AllowAll`, which always allows. That is
deliberate: the point of this crate isn't to implement policy now, it's
to make the seam structurally mandatory, so that wiring in a real policy
later is a matter of changing `check_read`'s logic (or swapping which
`PermissionCheck` impl callers pass in), not retrofitting checks into
every RPC handler that forgot to call one.

The future join point is multimatrix's (and eventually grorg's) RPC
handlers importing this crate and threading `&ReadGrant` through their
data-returning functions, once both sides exist. Not wired into either
repo yet.
