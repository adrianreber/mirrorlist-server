use super::*;
use std::error::Error;

#[test]
fn get_element_test() {
    let e: Vec<(i32, String)> = vec![
        (17, String::from("test23")),
        (17, String::from("test24")),
        (39, String::from("test7")),
    ];
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

fn get_db_connection() -> Result<PgConnection, Box<dyn Error>> {
    let database_url = env::var("TEST_DATABASE_URL")?;

    Ok(PgConnection::establish(&database_url)?)
}

#[test]
fn get_repositories_test() {
    let c = match get_db_connection() {
        Ok(c) => c,
        Err(e) => {
            println!("Database connection failed {}", e);
            panic!();
        }
    };

    use db::schema::repository;

    // Clean database
    assert!(!diesel::delete(repository::dsl::repository)
        .execute(&c)
        .is_err());

    let insert = diesel::insert_into(repository::dsl::repository).values((
        repository::dsl::category_id.eq(4),
        repository::dsl::version_id.eq(6),
        repository::dsl::arch_id.eq(8),
        repository::dsl::directory_id.eq(30001),
        repository::dsl::prefix.eq("pre".to_string()),
        repository::dsl::disabled.eq(false),
    ));

    assert!(!insert.execute(&c).is_err());

    let r = get_repositories(&c);
    assert_eq!(r[0].0.as_ref().unwrap(), &"pre".to_string());
    assert_eq!(r[0].1.unwrap(), 4);
    assert_eq!(r[0].2.unwrap(), 6);
    assert_eq!(r[0].3.unwrap(), 8);
    assert_eq!(r[0].4.unwrap(), 30001);
    assert!(!r[0].5);
}
