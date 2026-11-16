use access_control::{check, Decision, Identity, Policy, ResourceRef, Verb};

struct Read;
struct Manage;
impl Verb for Read {
    const NAME: &'static str = "read";
}
impl Verb for Manage {
    const NAME: &'static str = "manage";
}

struct OnlyRead;
impl Policy<Read> for OnlyRead {
    type Reason = &'static str;
    type Payload = ();
    fn decide(&self, _: &Identity, _: &ResourceRef) -> Decision<&'static str> {
        Decision::Allow
    }
    fn ask_reason(&self) -> &'static str {
        "asked"
    }
    fn payload(&self, _: &Identity, _: &ResourceRef) -> Result<(), &'static str> {
        Ok(())
    }
}

fn main() {
    let a = Identity::new("a").unwrap();
    let r = ResourceRef::new("r").unwrap();
    let _ = check::<Manage, _>(&OnlyRead, &a, &r);
}
