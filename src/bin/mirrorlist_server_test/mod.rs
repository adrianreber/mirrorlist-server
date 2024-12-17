use super::*;
use crate::common::protos::mirrormanager::{
    FileDetailsCacheDirectoryType, FileDetailsCacheFilesType, IntRepeatedIntMap,
};
use hyper::body;
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
    assert!(result.0.is_ipv4());
    assert!(!result.0.is_ipv6());
    assert_eq!(result.1, "553");
    ip = IpAddr::from_str("127.0.0.1").unwrap();
    result = find_in_ip_tree(&asn_cache, &ip);
    assert_eq!(result.1, "");
    ip = IpAddr::from_str("2001:7c0:700:1234::4321").unwrap();
    result = find_in_ip_tree(&asn_cache, &ip);
    assert!(!result.0.is_ipv4());
    assert!(result.0.is_ipv6());
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
    let mut mlc: Vec<MirrorListCacheType> = Vec::new();
    let mut ml1 = MirrorListCacheType::new();
    ml1.set_directory("directory/level/three".to_string());
    let mut ml2 = MirrorListCacheType::new();
    ml2.set_directory("directory/level/three/repodata".to_string());

    let global: Vec<i64> = vec![1, 42, 100];
    ml1.Global = global.clone();
    ml2.Global = global;

    let mut by_hostid: Vec<IntRepeatedIntMap> = Vec::new();
    let mut hcurl_id = IntRepeatedIntMap::new();
    hcurl_id.key = Some(42);
    hcurl_id.value = vec![421, 422, 423];
    by_hostid.push(hcurl_id);

    hcurl_id = IntRepeatedIntMap::new();
    hcurl_id.key = Some(1);
    hcurl_id.value = vec![11, 12, 13];
    by_hostid.push(hcurl_id);

    hcurl_id = IntRepeatedIntMap::new();
    hcurl_id.key = Some(100);
    hcurl_id.value = vec![1001, 1002, 1003];
    by_hostid.push(hcurl_id);

    ml1.ByHostId = by_hostid.clone();
    ml2.ByHostId = by_hostid;

    let mut by_country: Vec<StringRepeatedIntMap> = Vec::new();
    let mut bc = StringRepeatedIntMap::new();
    bc.key = Some("SE".to_string());
    bc.value = vec![42];
    by_country.push(bc);
    ml1.ByCountry = by_country.clone();
    ml2.ByCountry = by_country;

    mlc.push(ml1);
    mirrorlist.MirrorListCache = mlc.clone();

    let mut hbc: Vec<IntIntMap> = Vec::new();
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

    mirrorlist.HostBandwidthCache = hbc;

    let mut hcurl: Vec<IntStringMap> = Vec::new();
    let vec = vec![11, 12, 13, 1001, 1002, 1003, 421, 422, 423];
    for id in vec {
        let mut hc_url = IntStringMap::new();
        hc_url.set_key(id.into());
        hc_url.set_value(format!("http://hcurl{}/test-{}", id, id));
        hcurl.push(hc_url);
    }
    mirrorlist.HCUrlCache = hcurl;

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

    let mut p = DoMirrorlist {
        mirrorlist: &mirrorlist.clone(),
        remote: &remote,
        asn_cache: &asn_cache,
        geoip: &geoip_reader,
        cc: &cc,
        log_file: &log_file,
        minimum: 5,
    };

    let mut response = do_mirrorlist(request, &mut p);
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
    response = do_mirrorlist(request, &mut p);
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
    response = do_mirrorlist(request, &mut p);
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
    response = do_mirrorlist(request, &mut p);
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
    response = do_mirrorlist(request, &mut p);
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
    response = do_mirrorlist(request, &mut p);
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
    p.minimum = 1;
    response = do_mirrorlist(request, &mut p);
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
    p.minimum = 2;
    response = do_mirrorlist(request, &mut p);
    assert_eq!(response.status(), 200);
    assert!(Runtime::new()
            .unwrap()
            .block_on(read_response_body(response))
            .unwrap()
            .contains("# path = directory/level/three country = SE country = global \nhttp://hcurl421/test-421/\nhttp://hcurl"));

    request = Request::new(Body::empty());
    *request.uri_mut() = "/metalink?repo=repo-name&arch=arch-name&ip=89.160.20.113"
        .parse()
        .unwrap();
    response = do_mirrorlist(request, &mut p);
    assert_eq!(response.status(), 404);
    assert!(Runtime::new()
        .unwrap()
        .block_on(read_response_body(response))
        .unwrap()
        .contains("# repo = repo-name arch = arch-name error: invalid repo or arch"));

    let mut repo = StringStringMap::new();

    repo.set_key("repo-name+arch-name".to_string());
    repo.set_value("directory/level/three".to_string());
    let ratdn: Vec<StringStringMap> = vec![repo];
    mirrorlist.RepoArchToDirectoryName = ratdn;

    request = Request::new(Body::empty());
    *request.uri_mut() = "/metalink?repo=repo-name&arch=arch-name&ip=89.160.20.113"
        .parse()
        .unwrap();
    let m_tmp1 = &mirrorlist.clone();
    p.mirrorlist = m_tmp1;
    response = do_mirrorlist(request, &mut p);
    assert_eq!(response.status(), 500);
    assert!(Runtime::new()
        .unwrap()
        .block_on(read_response_body(response))
        .unwrap()
        .contains("mirrorlist cache index out of range, you broke it!"));

    mlc.push(ml2);
    mirrorlist.MirrorListCache = mlc;

    request = Request::new(Body::empty());
    *request.uri_mut() = "/metalink?repo=repo-name&arch=arch-name&ip=89.160.20.113"
        .parse()
        .unwrap();
    let m_tmp2 = &mirrorlist.clone();
    p.mirrorlist = m_tmp2;
    response = do_mirrorlist(request, &mut p);
    assert_eq!(response.status(), 404);
    assert!(Runtime::new()
        .unwrap()
        .block_on(read_response_body(response))
        .unwrap()
        .contains("repomd.xml not found or has not metalink"));

    let mut fdcdc: Vec<FileDetailsCacheDirectoryType> = Vec::new();
    let mut fdcd = FileDetailsCacheDirectoryType::new();
    fdcd.set_directory("directory/level/three/repodata".to_string());
    fdcdc.push(fdcd);

    let f: &mut FileDetailsCacheDirectoryType = &mut fdcdc[0];
    let fdcfc = &mut f.FileDetailsCacheFiles;
    let mut fdcf = FileDetailsCacheFilesType::new();
    fdcf.set_filename("repomd.xml".to_string());
    fdcfc.push(fdcf);

    let fdcf: &mut FileDetailsCacheFilesType = &mut fdcfc[0];
    let fdc = &mut fdcf.FileDetails;
    let mut file_detail_type = FileDetailsType::new();
    file_detail_type.set_Size(3);
    file_detail_type.set_TimeStamp(17);
    file_detail_type.set_MD5("MD5555".to_string());
    fdc.push(file_detail_type);

    mirrorlist.FileDetailsCache = fdcdc;

    request = Request::new(Body::empty());
    *request.uri_mut() = "/metalink?repo=repo-name&arch=arch-name&ip=89.160.20.113"
        .parse()
        .unwrap();
    p.mirrorlist = &mirrorlist;
    response = do_mirrorlist(request, &mut p);
    println!("{:#?}", response);
    assert_eq!(response.status(), 200);
    let response_body = Runtime::new()
        .unwrap()
        .block_on(read_response_body(response))
        .unwrap();
    assert!(response_body.contains("<hash type=\"md5\">MD5555</hash>"));

    assert!(response_body.contains("<mm0:timestamp>17</mm0:timestamp>"));

    assert!(response_body.contains("<size>3</size>"));

    assert!(response_body.contains("<file name=\"repomd.xml\">"));

    drop(file);
    drop(log_file);
    dir.close().unwrap();
}
