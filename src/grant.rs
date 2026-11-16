//! `Grant<V, P>` is an owned proof that a [`Policy`] for `V` allowed a caller
//! to perform that [`Verb`] on a resource. Outside [`check`] it is
//! unforgeable, but any [`Policy`] in scope that is implemented for `V` can
//! mint one through [`check`], and
//! [`crate::testing::AllowWith`] can mint a grant
//! for any `V` when the `testing` feature is enabled. Keep your [`Verb`]
//! types `pub(crate)` so that only your own policy can implement [`Policy`]
//! for them.
//!
//! [`check`] and [`Grant::still_allowed`] are the only points where an `Ask`
//! is settled: `check` refuses it with the policy's ask reason, and
//! `still_allowed` treats it as not allowed. `still_allowed` is pure over the
//! policy it is given; the grant caches no decision of its own.

use std::fmt;
use std::marker::PhantomData;

use crate::decision::{Decision, Reason};
use crate::denied::Denied;
use crate::id::{Identity, ResourceRef};

/// A named operation that a [`Policy`] can decide. Consumers declare their
/// own verb types, one per operation.
pub trait Verb: 'static {
    /// The stable name of this verb, used in debug output.
    const NAME: &'static str;
}

/// Decides whether a caller may perform verb `V` on a resource, and supplies
/// the payload carried by a grant.
pub trait Policy<V: Verb> {
    /// The reason this policy gives for a refusal.
    type Reason: Reason;
    /// The data carried by a grant minted under this policy.
    type Payload;

    /// Decides whether `caller` may perform `V` on `resource`. An `Ask` is
    /// settled by [`check`] using [`Policy::ask_reason`].
    fn decide(&self, caller: &Identity, resource: &ResourceRef) -> Decision<Self::Reason>;

    /// The reason this policy gives when it answers `Ask`.
    fn ask_reason(&self) -> Self::Reason;

    /// Computes the payload for a grant that has been allowed. An `Err`
    /// refuses the grant with that reason.
    fn payload(
        &self,
        caller: &Identity,
        resource: &ResourceRef,
    ) -> Result<Self::Payload, Self::Reason>;
}

/// An owned proof that a [`Policy`] for `V` allowed a caller to perform that
/// [`Verb`] on a resource, carrying a payload `P`. Outside [`check`] it is
/// unforgeable, but any [`Policy`] in scope that is implemented for `V` can
/// mint one through [`check`], and [`crate::testing::AllowWith`] can mint a
/// grant for any `V` when the `testing` feature is enabled.
pub struct Grant<V: Verb, P> {
    caller: Identity,
    resource: ResourceRef,
    payload: P,
    verb: PhantomData<fn() -> V>,
}

impl<V: Verb, P> Grant<V, P> {
    /// The caller this grant was minted for.
    pub fn caller(&self) -> &Identity {
        &self.caller
    }

    /// The resource this grant was minted for.
    pub fn resource(&self) -> &ResourceRef {
        &self.resource
    }

    /// The payload carried by this grant.
    pub fn payload(&self) -> &P {
        &self.payload
    }

    /// Consumes the grant and returns its payload.
    pub fn into_payload(self) -> P {
        self.payload
    }

    /// Asks `policy` afresh whether this grant is still allowed. Returns
    /// `true` only when the policy decides `Allow`; `Deny` and `Ask` give
    /// `false`. Nothing is cached, so the answer depends only on `policy`.
    pub fn still_allowed<Po: Policy<V> + ?Sized>(&self, policy: &Po) -> bool {
        matches!(policy.decide(&self.caller, &self.resource), Decision::Allow)
    }
}

impl<V: Verb, P: Clone> Clone for Grant<V, P> {
    fn clone(&self) -> Self {
        Self {
            caller: self.caller.clone(),
            resource: self.resource.clone(),
            payload: self.payload.clone(),
            verb: PhantomData,
        }
    }
}

impl<V: Verb, P: fmt::Debug> fmt::Debug for Grant<V, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Grant")
            .field("verb", &V::NAME)
            .field("caller", &self.caller)
            .field("resource", &self.resource)
            .field("payload", &self.payload)
            .finish()
    }
}

/// Checks whether `caller` may perform verb `V` on `resource` under `policy`.
/// On `Allow` the payload is computed and a [`Grant`] is returned. A `Deny`,
/// an `Ask` (refused with [`Policy::ask_reason`]) or a failing payload gives
/// a [`Denied`] carrying the reason.
pub fn check<V: Verb, Po: Policy<V> + ?Sized>(
    policy: &Po,
    caller: &Identity,
    resource: &ResourceRef,
) -> Result<Grant<V, Po::Payload>, Denied<Po::Reason>> {
    match policy.decide(caller, resource) {
        Decision::Allow => {
            let payload = policy.payload(caller, resource).map_err(Denied::new)?;
            Ok(Grant {
                caller: caller.clone(),
                resource: resource.clone(),
                payload,
                verb: PhantomData,
            })
        }
        Decision::Deny(r) => Err(Denied::new(r)),
        Decision::Ask(()) => Err(Denied::new(policy.ask_reason())),
    }
}
