//! Structurally-enforced authorization for grorg and multimatrix.
//!
//! The property this crate exists to provide: a function that returns
//! protected data can require a [`ReadGrant`] parameter, and there is no
//! way to construct a `ReadGrant` except by calling [`check_read`] and
//! having it succeed. Skipping the permission check is a compile error,
//! not a code-review discipline problem. The same holds for sending
//! ([`MessageGrant`] from [`check_message`]) and for managing
//! ([`ManageGrant`] from [`check_manage`]).
//!
//! The crate is synchronous and stores nothing. The scope of a grant (one
//! resource such as a room, or `any`) is the [`PermissionCheck`] policy's
//! business; the crate only sees the caller and the resource asked about.
//! Who may assign, create or oversee is decided by the embedding service's
//! own policy, not here.
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
//!
//! ```compile_fail
//! use access_control::{Identity, MessageGrant, ResourceRef};
//! let caller = Identity::new("a");
//! let resource = ResourceRef::new("room:r");
//! let _g = MessageGrant { caller: &caller, resource: &resource };
//! ```
//!
//! ```compile_fail
//! use access_control::{Identity, ManageGrant, ResourceRef};
//! let caller = Identity::new("a");
//! let resource = ResourceRef::new("room:r");
//! let _g = ManageGrant { caller: &caller, resource: &resource };
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

/// A pluggable authorization policy. [`check_read`], [`check_message`] and
/// [`check_manage`] consult this to decide whether to hand out the
/// matching grant.
///
/// `authorize_message` and `authorize_manage` default to [`Decision::Deny`]
/// so a policy that only knows about reads fails closed for the newer verbs.
pub trait PermissionCheck {
    fn authorize_read(&self, caller: &Identity, resource: &ResourceRef) -> Decision;

    /// May `caller` send a message to `resource`?
    fn authorize_message(&self, _caller: &Identity, _resource: &ResourceRef) -> Decision {
        Decision::Deny
    }

    /// May `caller` manage `resource` (its members, managers, closed state
    /// and history setting)?
    fn authorize_manage(&self, _caller: &Identity, _resource: &ResourceRef) -> Decision {
        Decision::Deny
    }
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

    fn authorize_message(&self, _caller: &Identity, _resource: &ResourceRef) -> Decision {
        Decision::Allow
    }

    fn authorize_manage(&self, _caller: &Identity, _resource: &ResourceRef) -> Decision {
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

/// Proof that sending a message to `resource` by `caller` was authorized.
///
/// Same structural property as [`ReadGrant`]: no public constructor, no
/// `Default`, not `Clone`; the only way to get one is [`check_message`]
/// succeeding.
pub struct MessageGrant<'a> {
    caller: &'a Identity,
    resource: &'a ResourceRef,
}

impl<'a> MessageGrant<'a> {
    pub fn caller(&self) -> &Identity {
        self.caller
    }

    pub fn resource(&self) -> &ResourceRef {
        self.resource
    }
}

/// Proof that managing `resource` by `caller` was authorized.
///
/// Same structural property as [`ReadGrant`]: no public constructor, no
/// `Default`, not `Clone`; the only way to get one is [`check_manage`]
/// succeeding.
pub struct ManageGrant<'a> {
    caller: &'a Identity,
    resource: &'a ResourceRef,
}

impl<'a> ManageGrant<'a> {
    pub fn caller(&self) -> &Identity {
        self.caller
    }

    pub fn resource(&self) -> &ResourceRef {
        self.resource
    }
}

/// The only way to obtain a [`MessageGrant`]. Consults
/// [`PermissionCheck::authorize_message`].
pub fn check_message<'a>(
    policy: &'a impl PermissionCheck,
    caller: &'a Identity,
    resource: &'a ResourceRef,
) -> Result<MessageGrant<'a>, Denied> {
    match policy.authorize_message(caller, resource) {
        Decision::Allow => Ok(MessageGrant { caller, resource }),
        Decision::Deny => Err(Denied),
    }
}

/// The only way to obtain a [`ManageGrant`]. Consults
/// [`PermissionCheck::authorize_manage`].
pub fn check_manage<'a>(
    policy: &'a impl PermissionCheck,
    caller: &'a Identity,
    resource: &'a ResourceRef,
) -> Result<ManageGrant<'a>, Denied> {
    match policy.authorize_manage(caller, resource) {
        Decision::Allow => Ok(ManageGrant { caller, resource }),
        Decision::Deny => Err(Denied),
    }
}

/// Authorization was denied (for any verb). Carries no reason today —
/// `AllowAll` never produces this — but is a distinct type so callers can match on it
/// rather than stringly-typed errors once a real policy exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied;

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "access denied")
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

    // ---- message / manage grants ----

    /// Allows exactly one verb, so a test can prove each check consults its
    /// own verb and no other.
    struct OnlyVerb(&'static str);

    impl PermissionCheck for OnlyVerb {
        fn authorize_read(&self, _c: &Identity, _r: &ResourceRef) -> Decision {
            verdict(self.0 == "read")
        }
        fn authorize_message(&self, _c: &Identity, _r: &ResourceRef) -> Decision {
            verdict(self.0 == "message")
        }
        fn authorize_manage(&self, _c: &Identity, _r: &ResourceRef) -> Decision {
            verdict(self.0 == "manage")
        }
    }

    fn verdict(allow: bool) -> Decision {
        if allow {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }

    #[test]
    fn allow_all_grants_message_and_manage() {
        let caller = Identity::new("agent-1");
        let room = ResourceRef::new("room:general");

        let m = check_message(&AllowAll, &caller, &room).expect("allow_all allows message");
        assert_eq!(m.caller(), &caller);
        assert_eq!(m.resource(), &room);

        let g = check_manage(&AllowAll, &caller, &room).expect("allow_all allows manage");
        assert_eq!(g.caller(), &caller);
        assert_eq!(g.resource(), &room);
    }

    #[test]
    fn denied_message_check_yields_no_grant() {
        let caller = Identity::new("agent-1");
        let room = ResourceRef::new("room:general");
        let result = check_message(&DenyAll, &caller, &room);
        assert_eq!(result.err(), Some(Denied));
    }

    #[test]
    fn denied_manage_check_yields_no_grant() {
        let caller = Identity::new("agent-1");
        let room = ResourceRef::new("room:general");
        let result = check_manage(&DenyAll, &caller, &room);
        assert_eq!(result.err(), Some(Denied));
    }

    #[test]
    fn each_check_consults_only_its_own_verb() {
        let caller = Identity::new("agent-1");
        let room = ResourceRef::new("room:general");

        let read_only = OnlyVerb("read");
        assert!(check_read(&read_only, &caller, &room).is_ok());
        assert!(check_message(&read_only, &caller, &room).is_err());
        assert!(check_manage(&read_only, &caller, &room).is_err());

        let message_only = OnlyVerb("message");
        assert!(check_read(&message_only, &caller, &room).is_err());
        assert!(check_message(&message_only, &caller, &room).is_ok());
        assert!(check_manage(&message_only, &caller, &room).is_err());

        let manage_only = OnlyVerb("manage");
        assert!(check_read(&manage_only, &caller, &room).is_err());
        assert!(check_message(&manage_only, &caller, &room).is_err());
        assert!(check_manage(&manage_only, &caller, &room).is_ok());
    }

    #[test]
    fn unimplemented_verbs_default_to_deny() {
        // A policy written before message/manage existed implements only
        // authorize_read; it must fail closed for the new verbs.
        struct ReadOnlyLegacy;
        impl PermissionCheck for ReadOnlyLegacy {
            fn authorize_read(&self, _c: &Identity, _r: &ResourceRef) -> Decision {
                Decision::Allow
            }
        }
        let caller = Identity::new("agent-1");
        let room = ResourceRef::new("room:general");
        assert!(check_read(&ReadOnlyLegacy, &caller, &room).is_ok());
        assert!(check_message(&ReadOnlyLegacy, &caller, &room).is_err());
        assert!(check_manage(&ReadOnlyLegacy, &caller, &room).is_err());
    }

    #[test]
    fn policy_sees_caller_and_resource_for_message_and_manage() {
        struct Exact {
            caller: Identity,
            resource: ResourceRef,
        }
        impl Exact {
            fn decide(&self, c: &Identity, r: &ResourceRef) -> Decision {
                verdict(c == &self.caller && r == &self.resource)
            }
        }
        impl PermissionCheck for Exact {
            fn authorize_read(&self, c: &Identity, r: &ResourceRef) -> Decision {
                self.decide(c, r)
            }
            fn authorize_message(&self, c: &Identity, r: &ResourceRef) -> Decision {
                self.decide(c, r)
            }
            fn authorize_manage(&self, c: &Identity, r: &ResourceRef) -> Decision {
                self.decide(c, r)
            }
        }
        let caller = Identity::new("agent-42");
        let room = ResourceRef::new("room:ops");
        let policy = Exact {
            caller: caller.clone(),
            resource: room.clone(),
        };
        let other_caller = Identity::new("agent-99");
        let other_room = ResourceRef::new("room:other");

        assert!(check_message(&policy, &caller, &room).is_ok());
        assert!(check_message(&policy, &other_caller, &room).is_err());
        assert!(check_message(&policy, &caller, &other_room).is_err());
        assert!(check_manage(&policy, &caller, &room).is_ok());
        assert!(check_manage(&policy, &other_caller, &room).is_err());
        assert!(check_manage(&policy, &caller, &other_room).is_err());
    }

    #[test]
    fn denied_display_is_verb_neutral() {
        assert_eq!(Denied.to_string(), "access denied");
    }
}
