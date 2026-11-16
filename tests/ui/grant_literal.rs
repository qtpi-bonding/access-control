use access_control::{Grant, Identity, ResourceRef, Verb};
use std::marker::PhantomData;

struct Read;
impl Verb for Read {
    const NAME: &'static str = "read";
}

fn main() {
    let _ = Grant::<Read, ()> {
        caller: Identity::new("a").unwrap(),
        resource: ResourceRef::new("r").unwrap(),
        payload: (),
        verb: PhantomData,
    };
}
