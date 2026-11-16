use access_control::{Grant, Verb};

struct Read;
impl Verb for Read {
    const NAME: &'static str = "read";
}

fn main() {
    let _ = Grant::<Read, ()>::default();
}
