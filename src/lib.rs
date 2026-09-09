//! Structurally-enforced read authorization for grorg and multimatrix.
//!
//! The property this crate exists to provide: a function that returns
//! protected data can require a [`ReadGrant`] parameter, and there is no
//! way to construct a `ReadGrant` except by calling [`check_read`] and
//! having it succeed. Skipping the permission check is a compile error,
//! not a code-review discipline problem.
//!
//! Today the only shipped [`PermissionCheck`] is [`AllowAll`] — there is
//! no authorization policy anywhere in the stack yet (grorg has
//! authentication only). The seam exists so that wiring in real policy
//! later means changing `check_read`'s logic, not retrofitting checks
//! into every RPC handler that forgot to call one.
//!
//! ```
//! use access_control::{check_read, AllowAll, Identity, ResourceRef};
//!
//! let policy = AllowAll;
//! let caller = Identity::new("agent-123");
//! let resource = ResourceRef::new("room:general");
//!
//! let grant = check_read(&policy, &caller, &resource).expect("allowed");
//! assert_eq!(grant.caller(), &caller);
//! ```
//!
//! Attempting to build a [`ReadGrant`] directly, without going through
//! [`check_read`], does not compile — there is no public constructor:
//!
//! ```compile_fail
//! use access_control::ReadGrant;
//! let _g: ReadGrant = ReadGrant {};
//! ```

/// An opaque caller identity. Not multimatrix's message-author id or
/// grorg's agent id — callers wrap their own identifiers into this type
/// at the point they need an authorization decision.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identity(String);

impl Identity {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An opaque reference to a protected resource (a room, a message tree,
/// a grorg Action). Not grorg's `ActionId` or multimatrix's `MessageId`
/// — callers wrap their own identifiers into this type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceRef(String);

impl ResourceRef {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The outcome of a permission check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// A pluggable authorization policy. [`check_read`] consults this to
/// decide whether to hand out a [`ReadGrant`].
pub trait PermissionCheck {
    fn authorize_read(&self, caller: &Identity, resource: &ResourceRef) -> Decision;
}

/// The no-op policy: always allows. This is the only [`PermissionCheck`]
/// this crate ships today, since there is no authorization policy
/// anywhere in the stack yet. Replacing this with a real policy later
/// does not require touching any call site that already threads a
/// [`ReadGrant`] through — only `check_read`'s caller changes which
/// `PermissionCheck` it passes in.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl PermissionCheck for AllowAll {
    fn authorize_read(&self, _caller: &Identity, _resource: &ResourceRef) -> Decision {
        Decision::Allow
    }
}

/// Proof that a read of `resource` by `caller` was authorized.
///
/// Deliberately has no public constructor, no `Default`, and does not
/// implement `Clone`. The only way to obtain one is [`check_read`]
/// succeeding. A function that returns protected data should require
/// `&ReadGrant` as a parameter, making it a compile error to call it
/// without an authorized grant in hand.
pub struct ReadGrant<'a> {
    caller: &'a Identity,
    resource: &'a ResourceRef,
}

impl<'a> ReadGrant<'a> {
    pub fn caller(&self) -> &Identity {
        self.caller
    }

    pub fn resource(&self) -> &ResourceRef {
        self.resource
    }
}

/// Authorization was denied. Carries no reason today — `AllowAll` never
/// produces this — but is a distinct type so callers can match on it
/// rather than stringly-typed errors once a real policy exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied;

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "read access denied")
    }
}

impl std::error::Error for Denied {}

/// The only way to obtain a [`ReadGrant`]. Consults `policy`; on
/// [`Decision::Allow`] returns a grant borrowing `caller` and `resource`,
/// on [`Decision::Deny`] returns [`Denied`].
pub fn check_read<'a>(
    policy: &'a impl PermissionCheck,
    caller: &'a Identity,
    resource: &'a ResourceRef,
) -> Result<ReadGrant<'a>, Denied> {
    match policy.authorize_read(caller, resource) {
        Decision::Allow => Ok(ReadGrant { caller, resource }),
        Decision::Deny => Err(Denied),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DenyAll;

    impl PermissionCheck for DenyAll {
        fn authorize_read(&self, _caller: &Identity, _resource: &ResourceRef) -> Decision {
            Decision::Deny
        }
    }

    #[test]
    fn allow_all_grants_read() {
        let policy = AllowAll;
        let caller = Identity::new("agent-1");
        let resource = ResourceRef::new("room:general");

        let grant = check_read(&policy, &caller, &resource).expect("allow_all should allow");
        assert_eq!(grant.caller(), &caller);
        assert_eq!(grant.resource(), &resource);
    }

    #[test]
    fn deny_all_returns_denied() {
        let policy = DenyAll;
        let caller = Identity::new("agent-1");
        let resource = ResourceRef::new("room:general");

        let result = check_read(&policy, &caller, &resource);
        assert_eq!(result.err(), Some(Denied));
    }

    #[test]
    fn policy_sees_the_actual_caller_and_resource() {
        struct RecordingPolicy {
            expected_caller: Identity,
            expected_resource: ResourceRef,
        }

        impl PermissionCheck for RecordingPolicy {
            fn authorize_read(&self, caller: &Identity, resource: &ResourceRef) -> Decision {
                if caller == &self.expected_caller && resource == &self.expected_resource {
                    Decision::Allow
                } else {
                    Decision::Deny
                }
            }
        }

        let caller = Identity::new("agent-42");
        let resource = ResourceRef::new("action:archebuild:spec:node");
        let policy = RecordingPolicy {
            expected_caller: caller.clone(),
            expected_resource: resource.clone(),
        };

        assert!(check_read(&policy, &caller, &resource).is_ok());

        let other_caller = Identity::new("agent-99");
        assert!(check_read(&policy, &other_caller, &resource).is_err());
    }
}
