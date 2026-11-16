mod common;

use access_control::{EmptyId, Identity, ResourceRef};

#[test]
fn empty_ids_are_refused() {
    assert_eq!(Identity::new(""), Err(EmptyId));
    assert_eq!(ResourceRef::new(String::new()), Err(EmptyId));
    assert!(Identity::try_from("").is_err());
}

#[test]
fn ids_round_trip_and_display_verbatim() {
    let id = Identity::new("agent-1").unwrap();
    assert_eq!(id.as_str(), "agent-1");
    assert_eq!(id.to_string(), "agent-1");
    assert_eq!(<Identity as AsRef<str>>::as_ref(&id), "agent-1");
    assert_eq!(Identity::try_from(String::from("agent-1")).unwrap(), id);
}

#[test]
fn ids_are_ordered() {
    let mut v = vec![Identity::new("b").unwrap(), Identity::new("a").unwrap()];
    v.sort();
    assert_eq!(v[0].as_str(), "a");
}
