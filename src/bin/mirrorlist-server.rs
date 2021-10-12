#![deny(warnings)]

pub mod lib;

use getopts::Options;
use hyper::header::{HeaderValue, CONTENT_TYPE, LOCATION};
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use ipnet::IpNet;
use itertools::Itertools;
use lib::common::{
    find_in_file_details_cache_directory_cache, find_in_int_int_map, find_in_int_repeated_int_map,
    find_in_int_repeated_string_map, find_in_int_string_map, find_in_mirrorlist_cache,
    find_in_string_bool_map, find_in_string_repeated_int_map, find_in_string_string_map,
};
use lib::protos::mirrormanager::{
    FileDetailsType, IntIntMap, IntRepeatedStringMap, IntStringMap, MirrorList,
    MirrorListCacheType, StringRepeatedIntMap, StringStringMap,
};
use log::{error, info};
use maxminddb::{geoip2, Reader};
use protobuf::parse_from_reader;
use rand::distributions::Distribution;
use rand::distributions::WeightedIndex;
use rand::seq::SliceRandom;
use rand::thread_rng;
use regex::Regex;
use std::cmp;
use std::collections::HashMap;
use std::convert::Infallible;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::process;
use std::str::FromStr;
use std::sync::Arc;
use treebitmap::IpLookupTable;

fn metalink_header() -> String {
    let mut header = String::new();
    let now = chrono::Utc::now();
    header.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    header.push_str("<metalink version=\"3.0\" xmlns=\"http://www.metalinker.org/\"");
    header.push_str(" type=\"dynamic\"");
    header.push_str(" pubdate=\"");
    header.push_str(&now.format("%a, %d %b %Y %H:%M:%S GMT").to_string());
    header.push_str("\" generator=\"mirrormanager\"");
    header.push_str(" xmlns:mm0=\"http://fedorahosted.org/mirrormanager\"");
    header.push_str(">\n");
    header
}

fn metalink_failuredoc(msg: String) -> String {
    let mut doc = String::new();
    doc.push_str(&metalink_header());
    doc.push_str("<!-- ");
    doc.push_str(&msg);
    doc.push_str("\n-->\n</metalink>\n");
    doc
}

fn get_param(params: &HashMap<&str, &str>, find: &str) -> String {
    let mut result = String::new();
    for param in params {
        if param.0 == &find {
            result.push_str(&param.1);
        }
    }
    result
}

fn check_for_param(params: &HashMap<&str, &str>, check: &str) -> bool {
    for param in params {
        if param.0 == &check {
            return true;
        }
    }
    false
}

fn find_in_netblock_country_cache(nbcc: &[StringStringMap], client_ip: &IpAddr) -> String {
    // In the python implementation this also uses a tree. In
    // Fedora's database this only contains one entry. No need
    // to implement it via tree, yet.. In
    for e in nbcc {
        let net: IpNet = match IpNet::from_str(&e.get_key()) {
            Ok(net) => net,
            _ => return "".to_string(),
        };
        if net.contains(client_ip) {
            return String::from(e.get_value());
        }
    }
    "".to_string()
}

fn find_in_ip_tree(
    tree: &(
        IpLookupTable<Ipv4Addr, String>,
        IpLookupTable<Ipv6Addr, String>,
    ),
    ip: &IpAddr,
) -> (IpAddr, String) {
    let result: (IpAddr, String) = match ip {
        IpAddr::V4(ip4) => {
            let tmp: (IpAddr, String) = match tree.0.longest_match(*ip4) {
                None => (IpAddr::from([0, 0, 0, 0]), "".to_string()),
                Some(tmp) => (IpAddr::from(tmp.0), tmp.2.to_string()),
            };
            tmp
        }
        IpAddr::V6(ip6) => {
            let tmp: (IpAddr, String) = match tree.1.longest_match(*ip6) {
                None => (IpAddr::from([0, 0, 0, 0]), "".to_string()),
                Some(tmp) => (IpAddr::from(tmp.0), tmp.2.to_string()),
            };
            tmp
        }
    };
    result
}

fn trim_by_client_country(
    hcac: &[IntRepeatedStringMap],
    hosts: &mut Vec<i64>,
    client_country: String,
) -> Vec<i64> {
    for host in hosts.clone() {
        // Check if this host is part of host_country_allowed_cache
        let index = find_in_int_repeated_string_map(&hcac, host);
        if index == -1 {
            // Host is not part of host_country_allowed_cache
            continue;
        }
        let mut found = false;
        for country in hcac[index as usize].get_value() {
            // Check if the client country is part of host_country_allowed_cache[host]
            if country == &client_country {
                // Yes it is. We do not need to remove this host from the list
                found = true;
            }
        }
        if found == false {
            // Looks like this host should be removed from the list of valid hosts
            let mut count = 0;
            for inner_loop_host in hosts.clone() {
                if inner_loop_host == host {
                    hosts.remove(count);
                    break;
                }
                count += 1;
            }
        }
    }
    hosts.to_vec()
}

fn do_global(hcac: &[IntRepeatedStringMap], global: &mut Vec<i64>, country: String) -> String {
    let header = String::from("country = global ");
    let hosts = trim_by_client_country(hcac, global, country);
    *global = hosts.clone();
    header
}

fn do_countrylist(
    by_country: &[StringRepeatedIntMap],
    hosts: &mut Vec<i64>,
    country: String,
) -> String {
    let mut header = String::new();
    // Check if the country exists at all in the by_country cache
    let i = find_in_string_repeated_int_map(by_country, &country.to_string().to_uppercase());
    if i != -1 {
        for host in by_country[i as usize].get_value() {
            // Add all hostids to the result
            hosts.push(*host);
        }
        header.push_str(&format!("country = {} ", country));
    }
    header
}

fn get_same_continent_hosts(
    by_country: &[StringRepeatedIntMap],
    cc: &HashMap<String, String>,
    country: String,
    mut hosts: &mut Vec<i64>,
) -> String {
    let mut header = String::new();
    let continent: String;
    if cc.contains_key(&country.to_uppercase()) {
        continent = String::from(&cc[&country.to_uppercase()]);
    } else {
        // The country does not exist in the country -> continent mapping.
        // This can happen as it relies on user input.
        return header;
    }
    // Now we know that the country exists in the mapping.
    // Get the continent and get all corresponding countries
    for c in cc.keys() {
        if cc[c] == continent && c != &country.to_uppercase() {
            let ret = do_countrylist(&by_country, &mut hosts, c.to_string());
            if ret != "" {
                header.push_str(&ret);
            }
        }
    }
    header
}

fn weigthed_shuffle(hosts: &mut Vec<i64>, hbc: &[IntIntMap], results: &mut Vec<i64>) {
    if hosts.len() == 0 {
        return;
    }
    let mut weights: Vec<i64> = Vec::new();
    for e in hosts.clone() {
        weights.push(find_in_int_int_map(&hbc, e));
    }
    let mut rng = &mut rand::thread_rng();
    let mut dist = WeightedIndex::new(&weights).unwrap();
    for _ in hosts.clone() {
        let host = hosts[dist.sample(&mut rng)];
        let index = hosts.iter().position(|&r| r == host).unwrap();
        results.push(host);
        hosts.remove(index);
        weights.remove(index);
        if weights.len() != 0 {
            dist = WeightedIndex::new(&weights).unwrap();
        }
    }
}

fn append_path(
    all_hosts: &Vec<i64>,
    cache: &MirrorListCacheType,
    hcurl_cache: &[IntStringMap],
    file: String,
    path_is_dir: bool,
) -> Vec<(i64, Vec<String>)> {
    let mut result: Vec<(i64, Vec<String>)> = Vec::new();
    let subpath = String::from(cache.get_Subpath());
    for hid in all_hosts {
        let mut hcurls: Vec<String> = Vec::new();
        let by_host_id = cache.get_ByHostId();
        let i = find_in_int_repeated_int_map(by_host_id, *hid);
        if i == -1 {
            continue;
        }

        for hcurl_id in by_host_id[i as usize].get_value() {
            let mut s = String::from(&find_in_int_string_map(&hcurl_cache, *hcurl_id));
            if subpath != "" {
                s.push_str("/");
                s.push_str(&subpath);
            }
            if file == "" && path_is_dir {
                s.push_str("/");
            }
            if file != "" {
                if !s.ends_with("/") {
                    s.push_str("/");
                }
                s.push_str(&file);
            }
            hcurls.push(s);
        }
        result.push((*hid, hcurls));
    }
    result
}

fn trim_to_preferred_protocols(
    hosts_and_urls: &mut Vec<(i64, Vec<String>)>,
    try_protocols: &Vec<&str>,
    max: usize,
) {
    let mut result: Vec<(i64, Vec<String>)> = Vec::new();
    let mut count: usize;
    for (host, hcurls) in hosts_and_urls.clone() {
        let mut url: Vec<String> = Vec::new();
        count = 0;
        for hcurl in hcurls {
            for p in try_protocols {
                let prot = String::from(&format!("{}:", p));
                if hcurl.starts_with(&prot) {
                    url.push(String::from(&hcurl.to_string()));
                    count += 1;
                    if count >= max {
                        break;
                    }
                }
            }
            if count >= max {
                break;
            }
        }
        if url.len() > 0 {
            result.push((host, url));
        }
    }
    if result.len() > 0 {
        *hosts_and_urls = result;
    }
}

fn http_response(metalink: bool, message: String, code: hyper::StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.body_mut() = match metalink {
        true => {
            response.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/metalink+xml"),
            );
            Body::from(metalink_failuredoc(message))
        }
        _ => Body::from(message),
    };
    *response.status_mut() = code;
    response
}

fn do_mirrorlist(
    req: Request<Body>,
    mirrorlist: &MirrorList,
    remote: &IpAddr,
    asn_cache: &(
        IpLookupTable<Ipv4Addr, String>,
        IpLookupTable<Ipv6Addr, String>,
    ),
    i2_cache: &(
        IpLookupTable<Ipv4Addr, String>,
        IpLookupTable<Ipv6Addr, String>,
    ),
    geoip2: &Reader<std::vec::Vec<u8>>,
    cc: &HashMap<String, String>,
    mut log_file: &File,
    minimum: usize,
) -> Response<Body> {
    let mut response = Response::new(Body::empty());

    let metalink = req.uri().path().ends_with("/metalink");

    // Return 404 for everything not ending in mirrorlist or metalink
    if !req.uri().path().ends_with("/mirrorlist") && !metalink {
        *response.status_mut() = StatusCode::NOT_FOUND;
        *response.body_mut() = Body::from("We don't serve their kind here!");
        return response;
    }

    // Split query string from url
    let params: Vec<&str> = match req.uri().query() {
        Some(q) => q.split("&").collect(),
        _ => Vec::new(),
    };

    // Fill query_params hashmap
    let mut query_params: HashMap<&str, &str> = HashMap::new();
    for param in params {
        let elements: Vec<&str> = param.split("=").collect();
        if elements.len() == 1 {
            query_params.insert(&elements[0], &"");
        } else {
            query_params.insert(&elements[0], &elements[1]);
        }
    }

    if !((check_for_param(&query_params, "repo") && check_for_param(&query_params, "arch"))
        || check_for_param(&query_params, "path"))
    {
        return http_response(
            metalink,
            "# either path=, or repo= and arch= must be specified".to_string(),
            StatusCode::OK,
        );
    }

    let mut file = String::new();
    let mut dir = String::new();
    let sdir: Vec<&str>;
    let mut path_is_dir = false;
    let mut header = String::new();
    let cache: &MirrorListCacheType;
    let mirrorlist_caches = &mirrorlist.get_MirrorListCache();

    if check_for_param(&query_params, "path") {
        let mut path = get_param(&query_params, "path");
        path = path.trim_matches('/').to_string();
        let re = Regex::new(r"/+").unwrap();
        path = re.replace_all(&path, "/").to_string();
        let index = find_in_mirrorlist_cache(&mirrorlist_caches, &path);

        header.push_str("# path = ");
        header.push_str(&path);
        header.push_str(" ");

        if index == -1 {
            // path was a file
            sdir = path.split("/").collect();
            file.push_str(&sdir[sdir.len() - 1].to_string());
            dir.push_str(&path.trim_end_matches(&file).trim_end_matches('/'));
            let index = find_in_mirrorlist_cache(&mirrorlist_caches, &dir);
            if index == -1 {
                return http_response(
                    metalink,
                    "error: invalid path".to_string(),
                    StatusCode::NOT_FOUND,
                );
            }
            cache = &mirrorlist_caches[index as usize];
        } else {
            // path was a directory
            path_is_dir = true;
            cache = &mirrorlist_caches[index as usize];
            dir.push_str(cache.get_directory());
        }
    } else {
        if get_param(&query_params, "repo").contains("source") {
            if check_for_param(&query_params, "arch") {
                query_params.remove(&"arch");
            }
            query_params.insert(&"arch", &"source");
        }
        let repo_redirect_cache = &mirrorlist.get_RepositoryRedirectCache();
        let mut repo =
            find_in_string_string_map(&repo_redirect_cache, &get_param(&query_params, "repo"));
        if repo == "" {
            repo = get_param(&query_params, "repo");
        }
        let arch = get_param(&query_params, "arch");
        header.push_str(&format!("# repo = {} arch = {} ", repo, arch));
        if find_in_string_bool_map(&mirrorlist.get_DisabledRepositoryCache(), &repo) {
            return http_response(metalink, "repo disabled".to_string(), StatusCode::OK);
        }
        let key = find_in_string_string_map(
            &mirrorlist.get_RepoArchToDirectoryName(),
            &format!("{}+{}", repo, arch),
        );
        if key == "" {
            let mut repos: Vec<String> = Vec::new();
            for e in mirrorlist.get_RepoArchToDirectoryName() {
                repos.push(e.get_key().to_string());
            }
            repos.sort();
            let mut repo_information = String::from(&header);
            repo_information.push_str("error: invalid repo or arch\n");
            repo_information.push_str("# following repositories are available:\n");
            for r in repos {
                let elements: Vec<&str> = r.split("+").collect();
                if elements.len() == 2 {
                    repo_information
                        .push_str(&format!("# repo={}&arch={}\n", elements[0], elements[1]));
                }
            }
            return http_response(metalink, repo_information, StatusCode::NOT_FOUND);
        }
        dir.push_str(&key);
        if metalink {
            if !dir.ends_with("/repodata") {
                dir.push_str("/repodata");
            }
            file.push_str("repomd.xml");
        } else {
            path_is_dir = true;
        }
        let index = find_in_mirrorlist_cache(&mirrorlist_caches, &dir);
        if index == -1 {
            *response.body_mut() = Body::from("mirrorlist cache index out of range, you broke it!");
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return response;
        }
        cache = &mirrorlist_caches[index as usize];
    }

    let mut ip_string = get_param(&query_params, "ip");
    if req.headers().contains_key("x-forwarded-for") && ip_string == "" {
        ip_string = String::from(req.headers()["x-forwarded-for"].to_str().unwrap());
        ip_string = String::from(ip_string.rsplit(", ").next().unwrap_or(&ip_string.as_str()));
    } else if ip_string == "" {
        ip_string.push_str(&remote.to_string());
    }

    // Make sure that we got a valid IP address
    let client_ip: IpAddr = match IpAddr::from_str(&ip_string) {
        Ok(ip) => ip,
        _ => {
            return http_response(
                metalink,
                "Cannot parse client IP address. Aborting.".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    };

    // The python implementation also had code to handle 'location'. This
    // was never ported to MirrorManager2 and has also not been ported
    // to this implementation.

    // The python implementation used to handle ordered_mirrorlist, but
    // that is obsolete with Fedora 7 EOL. Not really necessary to port
    // that to this implementation.

    let country = get_param(&query_params, "country");
    let mut requested_countries: Vec<&str> = Vec::new();
    if country != "" {
        requested_countries = country.split(",").collect();
        if requested_countries.len() != 0 {
            requested_countries.sort();
            requested_countries.dedup();
        }
    }

    let mut found_via = String::new();
    let mut mirrors_found = 0;
    let mut netblock_results: Vec<(String, i64)> = Vec::new();
    let mut asn_results: Vec<i64> = Vec::new();
    if requested_countries.len() == 0
        && (!check_for_param(&query_params, "netblock")
            || get_param(&query_params, "netblock") == "1")
    {
        let hnbc = &mirrorlist.get_HostNetblockCache();
        for hnb in *hnbc {
            let net: IpNet = match IpNet::from_str(hnb.get_key()) {
                Ok(net) => net,
                _ => {
                    let ip = match IpAddr::from_str(hnb.get_key()) {
                        Ok(ip) => ip,
                        _ => continue,
                    };
                    let mut with_mask = String::from(hnb.get_key());
                    if ip.is_ipv4() {
                        with_mask.push_str("/32");
                    } else {
                        with_mask.push_str("/128");
                    }
                    IpNet::from_str(&with_mask).unwrap()
                }
            };
            if net.contains(&client_ip) {
                for id in hnb.get_value() {
                    // Check if the host actually caries the requested content
                    if find_in_int_repeated_int_map(cache.get_ByHostId(), *id) > 0 {
                        netblock_results.push((String::from(&net.to_string()), *id));
                    }
                }
            }
        }

        if netblock_results.len() > 0 {
            header.push_str("Using preferred netblock ");
            found_via = String::from("netblocks");
        }

        mirrors_found += netblock_results.len();

        // Not enough mirrors where found using the netblock information.
        // Let's check ASN information for matches

        // First find the ASN from the global_netblocks file
        let asn = find_in_ip_tree(&asn_cache, &client_ip);
        if asn.1 != "" {
            let host_asn_cache = &mirrorlist.get_HostAsnCache();
            let asn_number = match asn.1.parse::<i64>() {
                Ok(x) => x,
                _ => -1,
            };
            let i = find_in_int_repeated_int_map(host_asn_cache, asn_number);
            if i != -1 {
                for id in host_asn_cache[i as usize].get_value() {
                    asn_results.push(*id);
                }
            }
        }
        if asn_results.len() != 0 {
            header.push_str(&format!("Using ASN {} ", asn.1));
            mirrors_found += asn_results.len();
            if found_via == "" {
                found_via = String::from("asn");
            }
        }
    }

    info!("mirrors_found after netblock {:#?}", mirrors_found);

    // First check if we assigned this IP to another country
    let mut client_country: String =
        find_in_netblock_country_cache(&mirrorlist.get_NetblockCountryCache(), &client_ip);
    if client_country == "" {
        // Do a GeoIP 2 lookup. In the Python implementation
        // this was more complicated as it was doing IPv6, Teredo
        // and IPv4 separately. Not necessary with GeoIP2.
        client_country = match geoip2.lookup::<geoip2::Country>(client_ip) {
            Ok(c) => match c.country {
                Some(co) => match co.iso_code {
                    Some(iso) => iso.to_string(),
                    _ => "N/A".to_string(),
                },
                _ => "N/A".to_string(),
            },
            _ => "N/A".to_string(),
        };
    }

    if check_for_param(&query_params, "repo") && check_for_param(&query_params, "arch") {
        let now = chrono::Utc::now();
        let log_msg = &format!(
            "IP: {}; DATE: {}; COUNTRY: {}; REPO: {}; ARCH: {}\n",
            client_ip,
            &now.format("%Y-%m-%d").to_string(),
            client_country,
            get_param(&query_params, "repo"),
            get_param(&query_params, "arch")
        );
        log_file.write_all(log_msg.as_bytes()).unwrap();
        log_file.flush().unwrap();
    }

    let mut i2_results: Vec<i64> = Vec::new();
    // Check if this is a Internet2 client
    let i2 = find_in_ip_tree(&i2_cache, &client_ip);
    if i2.1 != "" {
        let by_country_internet2 = &cache.get_ByCountryInternet2();
        let i = find_in_string_repeated_int_map(by_country_internet2, &client_country);
        if i != -1 {
            let hosts = trim_by_client_country(
                &mirrorlist.get_HostCountryAllowedCache(),
                &mut Vec::from(by_country_internet2[i as usize].get_value()),
                client_country.to_string(),
            );

            if hosts.len() > 0 {
                i2_results = hosts.clone();
                mirrors_found += i2_results.len();
                header.push_str("Using Internet2 ");
                if found_via == "" {
                    found_via = String::from("I2");
                }
            }
        }
    }

    info!("mirrors_found after Internet2 {:#?}", mirrors_found);

    let mut country_results: Vec<i64> = Vec::new();
    let mut continent_results: Vec<i64> = Vec::new();
    // If the user requested only mirrors for a certain country, this makes
    // sure that no continent or global mirrors are included. Even if the
    // user requested only mirrors for a certain country it will always
    // include the mirrors from the netblock/ASN/Internet2.
    let mut only_country = false;
    if requested_countries.len() > 0 {
        for country in &requested_countries {
            if &country.to_uppercase() == &"global".to_uppercase() {
                country_results.append(&mut cache.get_Global().to_vec());
                let ret = do_global(
                    &mirrorlist.get_HostCountryAllowedCache(),
                    &mut country_results,
                    client_country.to_string(),
                );
                header.push_str(&ret);
            }
            let ret = do_countrylist(
                &cache.get_ByCountry(),
                &mut country_results,
                country.to_string(),
            );
            if ret != "" {
                header.push_str(&ret);
            }
        }
        if country_results.len() == 0 {
            // No mirror in that country found, let's use all countries from the continent
            for country in requested_countries {
                let ret = get_same_continent_hosts(
                    &cache.get_ByCountry(),
                    &cc,
                    country.to_string(),
                    &mut continent_results,
                );
                if ret == "" {
                    continue;
                } else {
                    header.push_str(&ret);
                }
            }
        }
        if country_results.len() > 0 || continent_results.len() > 0 {
            let hcac = &mirrorlist.get_HostCountryAllowedCache();
            country_results =
                trim_by_client_country(&hcac, &mut country_results, client_country.to_string());
            continent_results =
                trim_by_client_country(&hcac, &mut continent_results, client_country.to_string());
            mirrors_found += country_results.len() + continent_results.len();
            // If there has been a mirror based on the country specified with country= and/or
            // the corresponding continent, do not any further mirrors to the list.
            // The user has explicitly selected a limited list of mirrors.
            only_country = true;
            if found_via == "" {
                found_via = String::from("country");
            }
        }
    }

    info!("mirrors_found after country {:#?}", mirrors_found);

    let mut geoip_results: Vec<i64> = Vec::new();
    if only_country == false {
        // Use GeoIP location do get a country list
        let ret = do_countrylist(
            &cache.get_ByCountry(),
            &mut geoip_results,
            client_country.to_string(),
        );
        if ret != "" {
            header.push_str(&ret);
        }
        if geoip_results.len() > 0 {
            mirrors_found += geoip_results.len();
            if found_via == "" {
                found_via = String::from("geoip");
            }
        }
    }
    info!("mirrors_found after geoip country {:#?}", mirrors_found);
    if only_country == false {
        // Use GeoIP location do get a country on continent list
        let ret = get_same_continent_hosts(
            &cache.get_ByCountry(),
            &cc,
            client_country.to_string(),
            &mut continent_results,
        );
        if ret != "" {
            header.push_str(&ret);
            mirrors_found += continent_results.len();
            if found_via == "" {
                found_via = String::from("continent");
            }
        }
    }
    info!("mirrors_found after geoip continent {:#?}", mirrors_found);

    {
        /* mirrors_found contains the number of mirrors which are
         * good mirrors concerning the location. Now check if those
         * mirrors actually carry the content we are looking for. */
        let mut actual_hosts: Vec<i64> = Vec::new();
        for e in &netblock_results {
            actual_hosts.push(e.1.clone());
        }

        actual_hosts.append(&mut asn_results.clone());
        actual_hosts.append(&mut i2_results.clone());
        actual_hosts.append(&mut country_results.clone());
        actual_hosts.append(&mut geoip_results.clone());
        actual_hosts.append(&mut continent_results.clone());

        let actual_hosts: Vec<_> = actual_hosts.into_iter().unique().collect();

        let mut hosts_and_urls = append_path(
            &actual_hosts,
            &cache,
            &mirrorlist.get_HCUrlCache(),
            file.clone(),
            path_is_dir,
        );
        if check_for_param(&query_params, "protocol") {
            let mut try_protocols: Vec<&str>;
            let protocols = get_param(&query_params, "protocol");
            try_protocols = protocols.split(",").collect();
            if try_protocols.len() != 0 {
                try_protocols.sort();
                try_protocols.dedup();
            }
            trim_to_preferred_protocols(&mut hosts_and_urls, &try_protocols, try_protocols.len());
        }
        mirrors_found = hosts_and_urls.len();
        info!(
            "Number of mirrors before global with the actual content: {}",
            mirrors_found
        );
    }

    let mut global_results: Vec<i64> = Vec::new();
    if mirrors_found < minimum && only_country == false {
        // Use mirrors from everywhere
        global_results = cache.get_Global().to_vec();
        let ret = do_global(
            &mirrorlist.get_HostCountryAllowedCache(),
            &mut global_results,
            client_country,
        );
        header.push_str(&ret);
        if found_via == "" || mirrors_found == 0 {
            found_via = String::from("global");
        }
        mirrors_found += global_results.len();
    }
    info!("Found {} possible mirrors", mirrors_found);

    info!(
        "mirrorlist: {} found its best mirror from {}",
        client_ip, found_via
    );

    let mut all_hosts: Vec<i64> = Vec::new();
    // All lookups have been performed, let's shuffle those lists.
    // Shuffle and order by prefix size
    netblock_results.shuffle(&mut thread_rng());
    netblock_results.sort_by_key(|k| IpNet::from_str(&k.0).unwrap().prefix_len());

    for e in netblock_results {
        all_hosts.push(e.1);
    }

    // Just shuffle
    asn_results.shuffle(&mut thread_rng());
    all_hosts.append(&mut asn_results);
    i2_results.shuffle(&mut thread_rng());
    all_hosts.append(&mut i2_results);

    {
        let hbc = &mirrorlist.get_HostBandwidthCache();
        // Weighted shuffle by bandwidth
        weigthed_shuffle(&mut country_results, &hbc, &mut all_hosts);
        weigthed_shuffle(&mut geoip_results, &hbc, &mut all_hosts);
        weigthed_shuffle(&mut continent_results, &hbc, &mut all_hosts);
        weigthed_shuffle(&mut global_results, &hbc, &mut all_hosts);
    }
    let all_hosts: Vec<_> = all_hosts.into_iter().unique().collect();

    let mut hosts_and_urls = append_path(
        &all_hosts,
        &cache,
        &mirrorlist.get_HCUrlCache(),
        file.clone(),
        path_is_dir,
    );

    let mut protocols_trimmed = false;
    if check_for_param(&query_params, "protocol") {
        let mut try_protocols: Vec<&str>;
        let protocols = get_param(&query_params, "protocol");
        try_protocols = protocols.split(",").collect();
        if try_protocols.len() != 0 {
            try_protocols.sort();
            try_protocols.dedup();
        }
        trim_to_preferred_protocols(&mut hosts_and_urls, &try_protocols, try_protocols.len());
        header.push_str("protocol = ");
        header.push_str(&protocols);
        protocols_trimmed = true;
    }

    if check_for_param(&query_params, "time") {
        header.push_str(&format!(
            "\n# database creation time: {}",
            &mirrorlist.get_Time()
        ));
    }

    if metalink {
        let (code, doc) = do_metalink(&cache, &mirrorlist, dir, file, &hosts_and_urls);
        *response.status_mut() = code;
        *response.body_mut() = Body::from(doc);
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/metalink+xml"),
        );
    } else {
        if check_for_param(&query_params, "redirect") {
            trim_to_preferred_protocols(&mut hosts_and_urls, &vec!["https", "http"], 1);
            protocols_trimmed = true;
        }
        if !protocols_trimmed {
            trim_to_preferred_protocols(&mut hosts_and_urls, &vec!["https", "http", "ftp"], 1);
        }
        if check_for_param(&query_params, "redirect") {
            let mut redirect = String::new();
            if hosts_and_urls.len() > 0 {
                for (_, urls) in hosts_and_urls {
                    for u in urls {
                        if u.starts_with("http") {
                            redirect += &u;
                            break;
                        }
                    }
                    if redirect != "" {
                        break;
                    }
                }
            }

            if redirect == "" {
                *response.status_mut() = StatusCode::NOT_FOUND;
            } else {
                *response.status_mut() = StatusCode::FOUND;
                response
                    .headers_mut()
                    .insert(LOCATION, HeaderValue::from_str(&redirect).unwrap());
            }
        } else {
            let mut answer = String::from(header);
            answer.push_str("\n");
            for (_, urls) in hosts_and_urls {
                for u in urls {
                    answer.push_str(&u);
                    answer.push_str("\n");
                }
            }
            *response.body_mut() = Body::from(answer);
        }
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    }

    response
}

fn metalink_details(fd: &FileDetailsType, indent: String) -> String {
    let mut result = String::new();
    if fd.get_TimeStamp() != 0 {
        result.push_str(&indent);
        result.push_str(&format!(
            " <mm0:timestamp>{}</mm0:timestamp>\n",
            fd.get_TimeStamp()
        ));
    }
    if fd.get_Size() != 0 {
        result.push_str(&indent);
        result.push_str(&format!(" <size>{}</size>\n", fd.get_Size()));
    }
    result.push_str(&indent);
    result.push_str(" <verification>\n");
    if fd.get_MD5() != "" {
        result.push_str(&indent);
        result.push_str(&format!("  <hash type=\"md5\">{}</hash>\n", fd.get_MD5()));
    }
    if fd.get_SHA1() != "" {
        result.push_str(&indent);
        result.push_str(&format!("  <hash type=\"sha1\">{}</hash>\n", fd.get_SHA1()));
    }
    if fd.get_SHA256() != "" {
        result.push_str(&indent);
        result.push_str(&format!(
            "  <hash type=\"sha256\">{}</hash>\n",
            fd.get_SHA256()
        ));
    }
    if fd.get_SHA512() != "" {
        result.push_str(&indent);
        result.push_str(&format!(
            "  <hash type=\"sha512\">{}</hash>\n",
            fd.get_SHA512()
        ));
    }
    result.push_str(&indent);
    result.push_str(" </verification>\n");
    result
}

fn do_metalink(
    cache: &MirrorListCacheType,
    mirrorlist: &MirrorList,
    dir: String,
    file: String,
    hosts_and_urls: &Vec<(i64, Vec<String>)>,
) -> (hyper::StatusCode, String) {
    let mut preference = 100;
    let fdcdc_index =
        find_in_file_details_cache_directory_cache(&mirrorlist.get_FileDetailsCache(), &dir);
    if fdcdc_index == -1 {
        return (
            StatusCode::NOT_FOUND,
            metalink_failuredoc(format!("{}/{} not found or has not metalink", dir, file)),
        );
    }
    let fdcf = &mirrorlist.get_FileDetailsCache()[fdcdc_index as usize]
        .get_FileDetailsCacheFiles()
        .to_vec();
    let mut wrong_file = true;
    for e in fdcf {
        if e.get_filename() == file {
            wrong_file = false;
        }
    }
    if wrong_file || fdcf.len() == 0 {
        return (
            StatusCode::NOT_FOUND,
            metalink_failuredoc(format!("{}/{} not found or has not metalink", dir, file)),
        );
    }
    let mut doc = metalink_header();
    doc.push_str(" <files>\n");
    doc.push_str(&format!("  <file name=\"{}\">\n", file));
    let mut count = 0;
    for e in fdcf {
        if e.get_filename() != file {
            continue;
        }
        for fd in e.get_FileDetails() {
            if count == 0 {
                // It does not make much sense that a filename can have multiple file_details
                // Just use the first one
                doc += &metalink_details(fd, "  ".to_string());
            } else {
                if count == 1 {
                    doc += "   <mm0:alternates>\n";
                }
                doc += "    <mm0:alternate>\n";
                doc += &metalink_details(fd, "     ".to_string());
                doc += "    </mm0:alternate>\n";
            }
            count += 1;
        }
    }
    if count > 1 {
        doc += "   </mm0:alternates>\n";
    }
    doc += "   <resources maxconnections=\"1\">\n";
    for (host, hcurls) in hosts_and_urls {
        let mut private = String::from(" mm0:private=\"True\"");
        for i in cache.get_Global() {
            if i == host {
                private = String::new();
            }
        }
        for url in hcurls {
            let protocol: Vec<&str> = url.split(":").collect();
            if protocol.len() == 0 {
                continue;
            }
            // Following comment is from the python implementation:
            // FIXME January 2010
            // adding protocol= here is not part of the Metalink 3.0 spec,
            // but MirrorManager 1.2.6 used it accidentally, as did
            // yum 3.2.20-3 as released in Fedora 8, 9, and 10.  After those
            // three are EOL (~January 2010), the extra protocol= can be
            // removed.
            //
            // Changing this will probably break old versions of yum...
            doc += "    <url protocol=\"";
            doc += protocol[0];
            doc += "\" type=\"";
            doc += protocol[0];
            doc += "\" location=\"";
            doc +=
                &find_in_int_string_map(&mirrorlist.get_HostCountryCache(), *host).to_uppercase();
            doc += &format!("\" preference=\"{}\"{}>", preference, private);
            doc += url;
            doc += "</url>\n";
        }
        preference = cmp::max(preference - 1, 1);
    }
    doc += "   </resources>\n";
    doc.push_str("  </file>\n");
    doc.push_str(" </files>\n");
    doc.push_str("</metalink>\n");
    (StatusCode::OK, doc)
}

fn create_ip_tree(
    file: &str,
) -> (
    IpLookupTable<Ipv4Addr, String>,
    IpLookupTable<Ipv6Addr, String>,
) {
    let mut tree_cache_4 = IpLookupTable::new();
    let mut tree_cache_6 = IpLookupTable::new();

    let f = match File::open(file) {
        Ok(file) => file,
        Err(e) => {
            error!("Opening {} failed : {}", file, e);
            return (tree_cache_4, tree_cache_6);
        }
    };

    let reader = BufReader::new(&f);
    for line in reader.lines() {
        let l = match line {
            Ok(line) => line,
            Err(e) => {
                error!("Error parsing {} : {}", file, e);
                tree_cache_4 = IpLookupTable::new();
                tree_cache_6 = IpLookupTable::new();
                return (tree_cache_4, tree_cache_6);
            }
        };
        let e: Vec<&str> = l.split_whitespace().collect();
        let net = match IpNet::from_str(e[0]) {
            Ok(n) => n,
            _ => continue,
        };
        if net.prefix_len() == 0 {
            continue;
        }
        // Put all networks and ASN number in a tree. Without tree
        // twice the memory is required and searching takes *much* longer.
        match net {
            IpNet::V4(net4) => {
                tree_cache_4.insert(net4.addr(), net4.prefix_len().into(), e[1].to_string())
            }
            IpNet::V6(net6) => {
                tree_cache_6.insert(net6.addr(), net6.prefix_len().into(), e[1].to_string())
            }
        };
    }

    (tree_cache_4, tree_cache_6)
}

fn setup_continents(file: &str, ccrc: &[StringStringMap]) -> HashMap<String, String> {
    let mut result: HashMap<String, String> = HashMap::new();

    let f = match File::open(file) {
        Ok(file) => file,
        Err(e) => {
            error!("Opening {} failed: {}", file, e);
            return result;
        }
    };
    let reader = BufReader::new(&f);
    for line in reader.lines() {
        let l = match line {
            Ok(line) => line,
            Err(e) => {
                error!("Error parsing {}: {}", file, e);
                result = HashMap::new();
                return result;
            }
        };
        let e: Vec<&str> = l.split(",").collect();
        // The country_continent CSV file uses 2 characters for all countries
        // and all continents.
        if e[0].len() != 2 {
            continue;
        }
        let mut continent = find_in_string_string_map(ccrc, &String::from(e[0]));
        if continent == "" {
            continent = String::from(e[1]);
        }
        result.insert(String::from(e[0]), continent);
    }
    result
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    // This is the minimum number of mirrors which should be returned
    let mut minimum: usize = 5;
    let mut geoip2_db = String::from("/usr/share/GeoIP/GeoLite2-Country.mmdb");
    let mut cache_file = String::from("/var/lib/mirrormanager/mirrorlist_cache.proto");
    let mut i2_netblocks = String::from("/var/lib/mirrormanager/i2_netblocks.txt");
    let mut global_netblocks = String::from("/var/lib/mirrormanager/global_netblocks.txt");
    let mut cccsv = String::from("/var/lib/mirrormanager/country_continent.csv");
    let mut logfile = String::from("/var/log/mirrormanager/mirrorlist.log");
    let mut listen = String::from("127.0.0.1");
    let mut port: usize = 3000;

    let args: Vec<String> = env::args().map(|x| x.to_string()).collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optmulti(
        "",
        "listen",
        &format!("IP address to listen to ({})", listen),
        "ADDRESS",
    );
    opts.optmulti(
        "",
        "port",
        &format!("TCP port to listen to ({})", port),
        "PORT",
    );
    opts.optmulti(
        "m",
        "minimum",
        &format!("minimum number of mirrors to return ({})", minimum),
        "NUMBER",
    );
    opts.optmulti(
        "c",
        "cache",
        &format!("protobuf cache file location ({})", cache_file),
        "CACHE",
    );
    opts.optmulti(
        "i",
        "internet2_netblocks",
        &format!("internet2 netblocks file location ({})", i2_netblocks),
        "CACHE",
    );
    opts.optmulti(
        "g",
        "global_netblocks",
        &format!("global netblocks file location ({})", global_netblocks),
        "CACHE",
    );
    opts.optmulti("l", "log", &format!("logfile ({})", logfile), "LOG");
    opts.optmulti(
        "",
        "cccsv",
        &format!("country continent csv file ({})", cccsv),
        "CSV",
    );
    opts.optmulti(
        "",
        "geoip",
        &format!("GeoIP country mmdb ({})", geoip2_db),
        "MMDB",
    );
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        _ => {
            print_usage(&program, opts);
            return;
        }
    };

    if matches.opt_present("m") {
        minimum = match matches.opt_strs("m")[matches.opt_count("m") - 1].parse::<usize>() {
            Ok(mi) => mi,
            _ => {
                println!(
                    "Error parsing minimum number of mirrors. Defaulting to {}",
                    minimum
                );
                minimum
            }
        };
    }

    if matches.opt_present("port") {
        port = match matches.opt_strs("port")[matches.opt_count("port") - 1].parse::<usize>() {
            Ok(po) => po,
            _ => {
                println!("Error parsing port. Defaulting to {}", port);
                port
            }
        };
    }

    if matches.opt_present("listen") {
        listen = matches.opt_strs("listen")[matches.opt_count("listen") - 1].to_string();
    }

    if matches.opt_present("geoip") {
        geoip2_db = matches.opt_strs("geoip")[matches.opt_count("geoip") - 1].to_string();
    }

    if matches.opt_present("cache") {
        cache_file = matches.opt_strs("cache")[matches.opt_count("cache") - 1].to_string();
    }

    if matches.opt_present("i") {
        i2_netblocks = matches.opt_strs("i")[matches.opt_count("i") - 1].to_string();
    }

    if matches.opt_present("g") {
        global_netblocks = matches.opt_strs("g")[matches.opt_count("g") - 1].to_string();
    }

    if matches.opt_present("cccsv") {
        cccsv = matches.opt_strs("cccsv")[matches.opt_count("cccsv") - 1].to_string();
    }

    if matches.opt_present("l") {
        logfile = matches.opt_strs("l")[matches.opt_count("l") - 1].to_string();
    }

    let log_file = Arc::new(
        match OpenOptions::new().append(true).create(true).open(&logfile) {
            Ok(lf) => lf,
            _ => {
                error!("Opening log file {} failed. Exiting!", logfile);
                process::exit(1);
            }
        },
    );

    info!("Loading protobuf input");
    let mut file = match File::open(&Path::new(&cache_file)) {
        Ok(f) => f,
        Err(e) => {
            error!("Opening {} failed: {}", &cache_file, e);
            process::exit(1)
        }
    };
    let mirrorlist = Arc::new(match parse_from_reader::<MirrorList>(&mut file) {
        Ok(f) => f,
        Err(e) => {
            error!("Parsing {} failed: {}", &cache_file, e);
            process::exit(1)
        }
    });

    info!(
        "Database creation time {} ({}) ",
        chrono::NaiveDateTime::from_timestamp(mirrorlist.get_Time() as i64, 0),
        &mirrorlist.get_Time()
    );

    info!("Loading geoip database");
    let geoip_reader = match maxminddb::Reader::open_readfile(&geoip2_db) {
        Ok(geoip_reader) => Arc::new(geoip_reader),
        _ => {
            error!("Reading GeoIP2 database {} failed", geoip2_db);
            process::exit(1);
        }
    };

    info!("Loading global netblocks");
    let asn_cache = Arc::new(create_ip_tree(&global_netblocks));
    info!("Loading I2 netblocks");
    let i2_cache = Arc::new(create_ip_tree(&i2_netblocks));

    if asn_cache.0.len() == 0 {
        error!("Creating ASN cache failed. Exiting!");
        process::exit(1);
    }

    if i2_cache.0.len() == 0 {
        error!("Creating Internet2 cache failed. Exiting!");
        process::exit(1);
    }

    info!("Loading country-continents");
    let cc_redirect = Arc::new(setup_continents(
        &cccsv,
        &mirrorlist.get_CountryContinentRedirectCache(),
    ));

    if cc_redirect.len() == 0 {
        error!("Parsing country continent data failed. Exiting!");
        process::exit(1);
    }

    let addr = String::from(&format!("{}:{}", listen, port));
    let addr: SocketAddr = addr.parse().expect("Unable to parse address!");

    let new_service = make_service_fn(move |socket: &AddrStream| {
        let remote_addr = socket.remote_addr();
        let val = mirrorlist.clone();
        let asn = asn_cache.clone();
        let i2 = i2_cache.clone();
        let geoip2 = geoip_reader.clone();
        let cc = cc_redirect.clone();
        let lf = log_file.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let response = do_mirrorlist(
                    req,
                    &val,
                    &remote_addr.ip(),
                    &asn,
                    &i2,
                    &geoip2,
                    &cc,
                    &lf,
                    minimum,
                );
                async move { Ok::<_, Infallible>(response) }
            }))
        }
    });

    let server = Server::bind(&addr).serve(new_service);

    println!("Listening on http://{}", addr);

    if let Err(err) = server.await {
        eprintln!("server error: {}", err);
    }
}

#[cfg(test)]
mod mirrorlist_server_test;
