//! Shared helpers for the integration tests.
#![allow(dead_code)]

use access_control::{Identity, ResourceRef};

pub fn id(s: &str) -> Identity {
    Identity::new(s).unwrap()
}

pub fn res(s: &str) -> ResourceRef {
    ResourceRef::new(s).unwrap()
}
