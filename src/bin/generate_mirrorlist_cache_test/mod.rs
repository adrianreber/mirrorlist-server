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

fn setup_db(c: &mut PgConnection, cat_id: i32) -> Result<usize, diesel::result::Error> {
    DEBUG.fetch_add(1, Ordering::SeqCst);
    use db::schema::{
        category, category_directory, directory, file_detail, host, host_category, repository, site,
    };

    let topdir = match cat_id {
        5 => String::from("test/topdir"),
        _ => String::new(),
    };

    // Clean database
    diesel::delete(repository::dsl::repository).execute(c)?;
    diesel::delete(host_category::dsl::host_category).execute(c)?;
    diesel::delete(host::dsl::host).execute(c)?;
    diesel::delete(site::dsl::site).execute(c)?;
    diesel::delete(category::dsl::category).execute(c)?;
    diesel::delete(category_directory::dsl::category_directory).execute(c)?;
    diesel::delete(directory::dsl::directory).execute(c)?;
    diesel::delete(file_detail::dsl::file_detail).execute(c)?;

    let insert1 = diesel::insert_into(repository::dsl::repository).values((
        repository::dsl::category_id.eq(cat_id),
        repository::dsl::version_id.eq(6),
        repository::dsl::arch_id.eq(8),
        repository::dsl::directory_id.eq(30001),
        repository::dsl::prefix.eq("pre".to_string()),
        repository::dsl::disabled.eq(false),
    ));
    insert1.execute(c)?;

    let insert2 = diesel::insert_into(host_category::dsl::host_category).values((
        host_category::dsl::id.eq(5193),
        host_category::dsl::host_id.eq(23),
        host_category::dsl::category_id.eq(cat_id),
        host_category::dsl::always_up2date.eq(false),
    ));
    insert2.execute(c)?;

    let insert3 = diesel::insert_into(host_category::dsl::host_category).values((
        host_category::dsl::id.eq(773),
        host_category::dsl::host_id.eq(56),
        host_category::dsl::category_id.eq(cat_id),
        host_category::dsl::always_up2date.eq(true),
    ));
    insert3.execute(c)?;

    let insert4 = diesel::insert_into(category::dsl::category).values((
        category::dsl::id.eq(cat_id),
        category::dsl::topdir_id.eq(69),
    ));
    insert4.execute(c)?;

    let insert5 = diesel::insert_into(directory::dsl::directory)
        .values((directory::dsl::id.eq(69), directory::dsl::name.eq(&topdir)));
    insert5.execute(c)?;

    let insert6 = diesel::insert_into(directory::dsl::directory).values((
        directory::dsl::id.eq(744),
        directory::dsl::name.eq(match topdir.is_empty() {
            true => "directory/repodata".to_string(),
            false => format!("{}/directory/repodata", topdir),
        }),
    ));
    insert6.execute(c)?;

    let insert7 = diesel::insert_into(file_detail::dsl::file_detail).values((
        file_detail::dsl::id.eq(72),
        file_detail::dsl::directory_id.eq(744),
        file_detail::dsl::filename.eq("repomd.xml".to_string()),
        file_detail::dsl::size.eq(177),
        file_detail::dsl::timestamp.eq(992465),
        file_detail::dsl::sha1.eq("sha1sum".to_string()),
        file_detail::dsl::sha256.eq("sha256sum".to_string()),
        file_detail::dsl::sha512.eq("sha512sum".to_string()),
    ));
    insert7.execute(c)?;

    let insert8 = diesel::insert_into(category_directory::dsl::category_directory).values((
        category_directory::dsl::category_id.eq(cat_id),
        category_directory::dsl::directory_id.eq(744),
    ));
    insert8.execute(c)?;

    let insert9 = diesel::insert_into(host::dsl::host).values((
        host::dsl::id.eq(3393),
        host::dsl::name.eq("test-host".to_string()),
        host::dsl::site_id.eq(9),
        host::dsl::user_active.eq(true),
        host::dsl::admin_active.eq(true),
        host::dsl::bandwidth_int.eq(33),
        host::dsl::country.eq("uQ".to_string()),
        host::dsl::asn_clients.eq(true),
        host::dsl::asn.eq(553),
        host::dsl::max_connections.eq(23),
        host::dsl::private.eq(false),
        host::dsl::internet2.eq(false),
        host::dsl::internet2_clients.eq(false),
    ));
    insert9.execute(c)?;

    let insert10 = diesel::insert_into(site::dsl::site).values((
        site::dsl::id.eq(9),
        site::dsl::user_active.eq(true),
        site::dsl::admin_active.eq(true),
        site::dsl::private.eq(false),
    ));
    insert10.execute(c)
}

#[test]
fn get_repositories_test() {
    let mut c = match get_db_connection() {
        Ok(c) => c,
        Err(e) => {
            println!("Database connection failed {}", e);
            panic!();
        }
    };

    let r = setup_db(&mut c, 4);

    if r.is_err() {
        println!("{:#?}", r);
    }
    assert!(r.is_ok());

    let r = get_repositories(&mut c);
    assert_eq!(r[0].0.as_ref().unwrap(), &"pre".to_string());
    assert_eq!(r[0].1.unwrap(), 4);
    assert_eq!(r[0].2.unwrap(), 6);
    assert_eq!(r[0].3.unwrap(), 8);
    assert_eq!(r[0].4.unwrap(), 30001);
    assert!(!r[0].5);
}

#[test]
fn get_host_categories_test() {
    let mut c = match get_db_connection() {
        Ok(c) => c,
        Err(e) => {
            println!("Database connection failed {}", e);
            panic!();
        }
    };

    let r = setup_db(&mut c, 4);

    if r.is_err() {
        println!("{:#?}", r);
    }
    assert!(r.is_ok());

    let hc = get_host_categories(&mut c);
    assert_eq!(hc.len(), 2);
    assert!(!hc[0].3);
    assert!(hc[1].3);
    assert!(hc[0].1.is_some());
    assert!(hc[0].2.is_some());
    assert!(hc[1].1.is_some());
    assert!(hc[1].2.is_some());
    assert_eq!(hc[0].1, Some(23));
    assert_eq!(hc[1].1, Some(56));
    assert_eq!(hc[0].2, Some(4));
    assert_eq!(hc[1].2, Some(4));
}

#[test]
fn get_mlc_test_empty_topdir() {
    let mut c = match get_db_connection() {
        Ok(c) => c,
        Err(e) => {
            println!("Database connection failed {}", e);
            panic!();
        }
    };

    let r = setup_db(&mut c, 4);

    if r.is_err() {
        println!("{:#?}", r);
    }
    assert!(r.is_ok());

    let hosts = get_hosts(&mut c);
    let directories = get_directories(&mut c);
    let host_category_urls = get_host_category_urls(&mut c);

    let (mlc, fdc) = get_mlc(&mut c, &hosts, &directories, &host_category_urls);

    assert_eq!(fdc.len(), 1);
    assert_eq!(fdc[0].directory(), "directory/repodata".to_string());
    assert_eq!(fdc[0].FileDetailsCacheFiles.len(), 1);
    let fdcf = &fdc[0].FileDetailsCacheFiles[0];
    assert_eq!(fdcf.filename.clone().unwrap(), "repomd.xml".to_string());
    let fdcfd = fdcf.FileDetails.clone();
    assert_eq!(fdcfd.len(), 1);
    assert_eq!(fdcfd[0].Size(), 177);

    assert_eq!(mlc.len(), 1);
    assert_eq!(mlc[0].Subpath(), "directory/repodata".to_string());
    assert_eq!(mlc[0].directory(), "directory/repodata".to_string());
    assert_eq!(mlc[0].Global[0], 56);
    assert_eq!(mlc[0].ByCountry[0].key.clone().unwrap(), "UQ");
    assert_eq!(mlc[0].ByCountry[0].value[0], 56);
}

#[test]
fn get_mlc_test_non_empty_topdir() {
    let mut c = match get_db_connection() {
        Ok(c) => c,
        Err(e) => {
            println!("Database connection failed {}", e);
            panic!();
        }
    };

    let r = setup_db(&mut c, 5);

    if r.is_err() {
        println!("{:#?}", r);
    }
    assert!(r.is_ok());

    let hosts = get_hosts(&mut c);
    let directories = get_directories(&mut c);
    let host_category_urls = get_host_category_urls(&mut c);

    let (mlc, fdc) = get_mlc(&mut c, &hosts, &directories, &host_category_urls);

    assert_eq!(fdc.len(), 1);
    assert_eq!(
        fdc[0].directory(),
        "test/topdir/directory/repodata".to_string()
    );
    assert_eq!(fdc[0].FileDetailsCacheFiles.len(), 1);
    let fdcf = &fdc[0].FileDetailsCacheFiles[0];
    assert_eq!(fdcf.filename.clone().unwrap(), "repomd.xml".to_string());
    let fdcfd = fdcf.FileDetails.clone();
    assert_eq!(fdcfd.len(), 1);
    assert_eq!(fdcfd[0].Size(), 177);

    assert_eq!(mlc.len(), 1);
    assert_eq!(
        mlc[0].directory(),
        "test/topdir/directory/repodata".to_string()
    );
    assert_eq!(mlc[0].Subpath(), "directory/repodata".to_string());
    assert_eq!(mlc[0].Global[0], 56);
    assert_eq!(mlc[0].ByCountry[0].key.clone().unwrap(), "UQ");
    assert_eq!(mlc[0].ByCountry[0].value[0], 56);
}
