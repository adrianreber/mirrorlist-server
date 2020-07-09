use super::*;
use crate::lib::protos::mirrormanager::IntRepeatedIntMap;
use hyper::body;
use protobuf::RepeatedField;
use tempfile::tempdir;
use tokio::runtime::Runtime;

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

#[test]
fn find_in_ip_tree_test() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("global");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "134.107.226.0/23 5520").unwrap();
    writeln!(file, "134.108.0.0/16 553").unwrap();
    writeln!(file, "134.109.0.0/16 680").unwrap();
    writeln!(file, "134.110.0.0/16 680").unwrap();
    writeln!(file, "134.111.0.0/16 394990").unwrap();
    writeln!(file, "134.112.0.0/16 10455").unwrap();
    writeln!(file, "2001:07c0::/29 553").unwrap();
    file.flush().unwrap();
    let asn_cache = create_ip_tree(file_path.to_str().unwrap());
    let mut ip = IpAddr::from_str("134.108.34.134").unwrap();
    let mut result = find_in_ip_tree(&asn_cache, &ip);
    assert_eq!(result.0.is_ipv4(), true);
    assert_eq!(result.0.is_ipv6(), false);
    assert_eq!(result.1, "553");
    ip = IpAddr::from_str("127.0.0.1").unwrap();
    result = find_in_ip_tree(&asn_cache, &ip);
    assert_eq!(result.1, "");
    ip = IpAddr::from_str("2001:7c0:700:1234::4321").unwrap();
    result = find_in_ip_tree(&asn_cache, &ip);
    assert_eq!(result.0.is_ipv4(), false);
    assert_eq!(result.0.is_ipv6(), true);
    assert_eq!(result.1, "553");
    drop(file);
    dir.close().unwrap();
}

pub async fn read_response_body(res: Response<Body>) -> Result<String, hyper::Error> {
    let bytes = body::to_bytes(res.into_body()).await?;
    Ok(String::from_utf8(bytes.to_vec()).expect("response was not valid utf-8"))
}

#[test]
fn do_mirrorlist_test() {
    let mut mirrorlist = MirrorList::new();
    let mut mlc: RepeatedField<MirrorListCacheType> = RepeatedField::new();
    let mut ml = MirrorListCacheType::new();
    ml.set_directory("directory/level/three".to_string());

    let mut global: Vec<i64> = Vec::new();
    global.push(1);
    global.push(42);
    global.push(100);
    ml.set_Global(global);

    let mut by_hostid: RepeatedField<IntRepeatedIntMap> = RepeatedField::new();
    let mut hcurl_id = IntRepeatedIntMap::new();
    hcurl_id.set_key(42);
    hcurl_id.set_value(vec![421, 422, 423]);
    by_hostid.push(hcurl_id);

    hcurl_id = IntRepeatedIntMap::new();
    hcurl_id.set_key(1);
    hcurl_id.set_value(vec![11, 12, 13]);
    by_hostid.push(hcurl_id);

    hcurl_id = IntRepeatedIntMap::new();
    hcurl_id.set_key(100);
    hcurl_id.set_value(vec![1001, 1002, 1003]);
    by_hostid.push(hcurl_id);

    ml.set_ByHostId(by_hostid);

    let mut by_country: RepeatedField<StringRepeatedIntMap> = RepeatedField::new();
    let mut bc = StringRepeatedIntMap::new();
    bc.set_key("SE".to_string());
    bc.set_value(vec![42]);
    by_country.push(bc);
    ml.set_ByCountry(by_country);

    mlc.push(ml);
    mirrorlist.set_MirrorListCache(mlc);

    let mut hbc: RepeatedField<IntIntMap> = RepeatedField::new();
    let mut hb = IntIntMap::new();
    hb.set_key(1);
    hb.set_value(100);
    hbc.push(hb);
    hb = IntIntMap::new();
    hb.set_key(42);
    hb.set_value(83);
    hbc.push(hb);
    hb = IntIntMap::new();
    hb.set_key(100);
    hb.set_value(1000);
    hbc.push(hb);

    mirrorlist.set_HostBandwidthCache(hbc);

    let mut hcurl: RepeatedField<IntStringMap> = RepeatedField::new();
    let vec = vec![11, 12, 13, 1001, 1002, 1003, 421, 422, 423];
    for id in vec {
        let mut hc_url = IntStringMap::new();
        hc_url.set_key(id.into());
        hc_url.set_value(format!("http://hcurl{}/test-{}", id, id));
        hcurl.push(hc_url);
    }
    mirrorlist.set_HCUrlCache(hcurl);

    let mut request = Request::new(Body::empty());

    let remote = IpAddr::from_str("134.108.34.134").unwrap();

    let dir = tempdir().unwrap();
    let file_path = dir.path().join("global");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "134.107.226.0/23 5520").unwrap();
    writeln!(file, "134.108.0.0/16 553").unwrap();
    writeln!(file, "134.109.0.0/16 680").unwrap();
    writeln!(file, "134.110.0.0/16 680").unwrap();
    writeln!(file, "89.160.20.112/124 131313").unwrap();
    writeln!(file, "134.111.0.0/16 394990").unwrap();
    writeln!(file, "134.112.0.0/16 10455").unwrap();
    writeln!(file, "2001:07c0::/29 553").unwrap();
    file.flush().unwrap();

    let asn_cache = create_ip_tree(file_path.to_str().unwrap());
    let geoip_reader =
        maxminddb::Reader::open_readfile("testdata/GeoIP2-Country-Test.mmdb").unwrap();
    let cc: HashMap<String, String> = HashMap::new();
    let log_file = File::create(dir.path().join("join")).unwrap();

    let mut response = do_mirrorlist(
        request,
        &mirrorlist,
        &remote,
        &asn_cache,
        &asn_cache,
        &geoip_reader,
        &cc,
        &log_file,
        5,
    );
    assert_eq!(response.status(), 404);
    assert_eq!(
        Runtime::new()
            .unwrap()
            .block_on(read_response_body(response))
            .unwrap(),
        "We don't serve their kind here!"
    );

    request = Request::new(Body::empty());
    *request.uri_mut() = "/mirrorlist".parse().unwrap();
    response = do_mirrorlist(
        request,
        &mirrorlist,
        &remote,
        &asn_cache,
        &asn_cache,
        &geoip_reader,
        &cc,
        &log_file,
        5,
    );
    assert_eq!(response.status(), 200);
    assert_eq!(
        Runtime::new()
            .unwrap()
            .block_on(read_response_body(response))
            .unwrap(),
        "# either path=, or repo= and arch= must be specified"
    );

    request = Request::new(Body::empty());
    *request.uri_mut() = "/metalink".parse().unwrap();
    response = do_mirrorlist(
        request,
        &mirrorlist,
        &remote,
        &asn_cache,
        &asn_cache,
        &geoip_reader,
        &cc,
        &log_file,
        5,
    );
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-type"],
        "application/metalink+xml"
    );
    assert!(Runtime::new()
        .unwrap()
        .block_on(read_response_body(response))
        .unwrap()
        .contains("<!-- # either path=, or repo= and arch= must be specified\n-->\n</metalink>\n"));

    request = Request::new(Body::empty());
    *request.uri_mut() = "/mirrorlist?path=n/a".parse().unwrap();
    response = do_mirrorlist(
        request,
        &mirrorlist,
        &remote,
        &asn_cache,
        &asn_cache,
        &geoip_reader,
        &cc,
        &log_file,
        5,
    );
    assert_eq!(response.status(), 404);
    assert_eq!(
        Runtime::new()
            .unwrap()
            .block_on(read_response_body(response))
            .unwrap(),
        "error: invalid path"
    );

    request = Request::new(Body::empty());
    *request.uri_mut() = "/mirrorlist?path=directory/level/three&ip=10.11.12.331"
        .parse()
        .unwrap();
    response = do_mirrorlist(
        request,
        &mirrorlist,
        &remote,
        &asn_cache,
        &asn_cache,
        &geoip_reader,
        &cc,
        &log_file,
        5,
    );
    assert_eq!(response.status(), 500);
    assert_eq!(
        Runtime::new()
            .unwrap()
            .block_on(read_response_body(response))
            .unwrap(),
        "Cannot parse client IP address. Aborting."
    );

    request = Request::new(Body::empty());
    *request.uri_mut() = "/mirrorlist?path=directory/level/three&country=sE"
        .parse()
        .unwrap();
    response = do_mirrorlist(
        request,
        &mirrorlist,
        &remote,
        &asn_cache,
        &asn_cache,
        &geoip_reader,
        &cc,
        &log_file,
        5,
    );
    assert_eq!(response.status(), 200);
    assert_eq!(
        Runtime::new()
            .unwrap()
            .block_on(read_response_body(response))
            .unwrap(),
        "# path = directory/level/three country = sE \nhttp://hcurl421/test-421/\n"
    );

    request = Request::new(Body::empty());
    *request.uri_mut() = "/mirrorlist?path=directory/level/three&ip=89.160.20.113"
        .parse()
        .unwrap();
    response = do_mirrorlist(
        request,
        &mirrorlist,
        &remote,
        &asn_cache,
        &asn_cache,
        &geoip_reader,
        &cc,
        &log_file,
        1,
    );
    assert_eq!(response.status(), 200);
    assert_eq!(
        Runtime::new()
            .unwrap()
            .block_on(read_response_body(response))
            .unwrap(),
        "# path = directory/level/three country = SE \nhttp://hcurl421/test-421/\n"
    );

    request = Request::new(Body::empty());
    *request.uri_mut() = "/mirrorlist?path=directory/level/three&ip=89.160.20.113"
        .parse()
        .unwrap();
    response = do_mirrorlist(
        request,
        &mirrorlist,
        &remote,
        &asn_cache,
        &asn_cache,
        &geoip_reader,
        &cc,
        &log_file,
        2,
    );
    assert_eq!(response.status(), 200);
    assert!(Runtime::new()
            .unwrap()
            .block_on(read_response_body(response))
            .unwrap()
            .contains("# path = directory/level/three country = SE country = global \nhttp://hcurl421/test-421/\nhttp://hcurl"));

    drop(file);
    drop(log_file);
    dir.close().unwrap();
}
