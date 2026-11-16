use access_control::{Decision, Grant, Verb};

struct Read;
impl Verb for Read {
    const NAME: &'static str = "read";
}

fn main() {
    let _: Grant<Read, ()> = Decision::<&'static str>::Allow.into();
}
