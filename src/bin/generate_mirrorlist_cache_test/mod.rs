use super::*;

#[test]
fn get_element_test() {
    let mut e: Vec<(i32, String)> = Vec::new();
    e.push((17, String::from("test23")));
    e.push((17, String::from("test24")));
    e.push((39, String::from("test7")));
    let mut element = get_element(17, &e);
    assert_eq!(2, element.len());
    assert!(element[0].contains(&String::from("test23")));
    assert!(element[1].contains(&String::from("test24")));
    assert!(!element[0].contains(&String::from("test7")));
    element = get_element(39, &e);
    assert_eq!(1, element.len());
    assert!(element[0].contains(&String::from("test7")));
    assert!(!element[0].contains(&String::from("test23")));
    element = get_element(42, &e);
    assert_eq!(0, element.len());
}
