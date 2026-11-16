//! Non-empty identifier types used by the access-control API.

use std::fmt;

/// Error returned when an identifier is constructed from an empty string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyId;

impl fmt::Display for EmptyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "identifier is empty")
    }
}

impl std::error::Error for EmptyId {}

/// An opaque caller identity. Never empty. Callers wrap their own
/// identifiers into this type at the point they need an authorization
/// decision.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Identity(String);

impl Identity {
    /// Creates an identity, failing with [`EmptyId`] if `id` is empty.
    pub fn new(id: impl Into<String>) -> Result<Self, EmptyId> {
        let s = id.into();
        if s.is_empty() {
            Err(EmptyId)
        } else {
            Ok(Self(s))
        }
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Identity {
    type Error = EmptyId;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for Identity {
    type Error = EmptyId;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl AsRef<str> for Identity {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An opaque reference to a protected resource. Never empty. Callers wrap
/// their own resource identifiers into this type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceRef(String);

impl ResourceRef {
    /// Creates a resource reference, failing with [`EmptyId`] if `id` is empty.
    pub fn new(id: impl Into<String>) -> Result<Self, EmptyId> {
        let s = id.into();
        if s.is_empty() {
            Err(EmptyId)
        } else {
            Ok(Self(s))
        }
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ResourceRef {
    type Error = EmptyId;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for ResourceRef {
    type Error = EmptyId;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl AsRef<str> for ResourceRef {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
