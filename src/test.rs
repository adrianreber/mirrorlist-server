use super::*;

#[test]
fn metalink_header_test() {
    let mut start = String::new();
    let mut end = String::new();
    start.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    start.push_str("<metalink version=\"3.0\" xmlns=\"http://www.metalinker.org/\"");
    start.push_str(" type=\"dynamic\"");
    start.push_str(" pubdate=\"");
    end.push_str("\" generator=\"mirrormanager\"");
    end.push_str(" xmlns:mm0=\"http://fedorahosted.org/mirrormanager\"");
    end.push_str(">\n");
    let s = metalink_header();
    assert!(s.contains(&start));
    assert!(s.contains(&end));
}

#[test]
fn metalink_failuredoc_test() {
    let mut start = String::new();
    let mut end = String::new();
    let test = String::from("metalink failure test");
    start.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    start.push_str("<metalink version=\"3.0\" xmlns=\"http://www.metalinker.org/\"");
    start.push_str(" type=\"dynamic\"");
    start.push_str(" pubdate=\"");
    end.push_str("\" generator=\"mirrormanager\"");
    end.push_str(" xmlns:mm0=\"http://fedorahosted.org/mirrormanager\"");
    end.push_str(">\n");
    let s = metalink_failuredoc(test.clone());
    assert!(s.contains(&start));
    assert!(s.contains(&end));
    let result = format!("<!-- {}\n-->\n</metalink>\n", &test);
    assert!(s.contains(&result));
}
