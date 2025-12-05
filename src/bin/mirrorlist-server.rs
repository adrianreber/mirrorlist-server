#![deny(warnings)]

pub mod common;

use common::functions::{
    find_in_file_details_cache_directory_cache, find_in_int_int_map, find_in_int_repeated_int_map,
    find_in_int_repeated_string_map, find_in_int_string_map, find_in_mirrorlist_cache,
    find_in_string_bool_map, find_in_string_repeated_int_map, find_in_string_string_map,
};
use common::protos::mirrormanager::{
    FileDetailsType, IntIntMap, IntRepeatedStringMap, IntStringMap, MirrorList,
    MirrorListCacheType, StringRepeatedIntMap, StringStringMap,
};
use getopts::Options;
use hyper::header::{HeaderValue, CONTENT_TYPE, LOCATION};
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use ipnet::IpNet;
use itertools::Itertools;
use log::{error, info};
use maxminddb::{geoip2, Reader};
use rand::distr::weighted::WeightedIndex;
use rand::distr::Distribution;
use rand::seq::SliceRandom;
use regex::Regex;
use std::cmp;
use std::collections::HashMap;
use std::convert::Infallible;
use std::env;
use std::fmt::Write as _;
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
    params.get(find).copied().unwrap_or("").to_string()
}

fn find_in_netblock_country_cache(nbcc: &[StringStringMap], client_ip: &IpAddr) -> String {
    // In the python implementation this also uses a tree. In
    // Fedora's database this only contains one entry. No need
    // to implement it via tree, yet.. In
    for e in nbcc {
        let net: IpNet = match IpNet::from_str(e.key()) {
            Ok(net) => net,
            _ => return "".to_string(),
        };
        if net.contains(client_ip) {
            return e.value.clone().unwrap();
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
    hosts.retain(|&host| {
        // Check if this host is part of host_country_allowed_cache
        let index = find_in_int_repeated_string_map(hcac, host);
        if index == -1 {
            // Host is not part of host_country_allowed_cache, keep it
            return true;
        }
        // Check if the client country is part of host_country_allowed_cache[host]
        for country in &hcac[index as usize].value {
            if country == &client_country {
                // Yes it is. We do not need to remove this host from the list
                return true;
            }
        }
        // Client country not found, remove this host
        false
    });
    hosts.to_vec()
}

fn do_global(hcac: &[IntRepeatedStringMap], global: &mut Vec<i64>, country: String) -> String {
    let header = String::from("country = global ");
    let hosts = trim_by_client_country(hcac, global, country);
    *global = hosts;
    header
}

fn do_countrylist(
    by_country: &[StringRepeatedIntMap],
    hosts: &mut Vec<i64>,
    country: String,
) -> String {
    let mut header = String::new();
    // Check if the country exists at all in the by_country cache
    let i = find_in_string_repeated_int_map(by_country, &country.to_uppercase());
    if i != -1 {
        for host in &by_country[i as usize].value {
            // Add all hostids to the result
            hosts.push(*host);
        }
        let _ = write!(header, "country = {country} ");
    }
    header
}

fn get_same_continent_hosts(
    by_country: &[StringRepeatedIntMap],
    cc: &HashMap<String, String>,
    country: String,
    hosts: &mut Vec<i64>,
) -> String {
    let mut header = String::new();
    let continent: String = if cc.contains_key(&country.to_uppercase()) {
        String::from(&cc[&country.to_uppercase()])
    } else {
        // The country does not exist in the country -> continent mapping.
        // This can happen as it relies on user input.
        return header;
    };
    // Now we know that the country exists in the mapping.
    // Get the continent and get all corresponding countries
    for c in cc.keys() {
        if cc[c] == continent && c != &country.to_uppercase() {
            let ret = do_countrylist(by_country, hosts, c.to_string());
            if !ret.is_empty() {
                header.push_str(&ret);
            }
        }
    }
    header
}

fn weighted_shuffle(hosts: &mut Vec<i64>, hbc: &[IntIntMap], results: &mut Vec<i64>) {
    if hosts.is_empty() {
        return;
    }
    let mut weights: Vec<i64> = Vec::new();
    for &e in hosts.iter() {
        weights.push(find_in_int_int_map(hbc, e));
    }
    let mut rng = &mut rand::rng();
    let mut dist = WeightedIndex::new(&weights).unwrap();
    while !hosts.is_empty() {
        let host = hosts[dist.sample(&mut rng)];
        let index = hosts.iter().position(|&r| r == host).unwrap();
        results.push(host);
        hosts.remove(index);
        weights.remove(index);
        if !weights.is_empty() {
            dist = WeightedIndex::new(&weights).unwrap();
        }
    }
}

fn append_path(
    all_hosts: &[i64],
    cache: &MirrorListCacheType,
    hcurl_cache: &[IntStringMap],
    file: &str,
    path_is_dir: bool,
) -> Vec<(i64, Vec<String>)> {
    let mut result: Vec<(i64, Vec<String>)> = Vec::new();
    let subpath = String::from(cache.Subpath());
    for hid in all_hosts {
        let mut hcurls: Vec<String> = Vec::new();
        let by_host_id = &cache.ByHostId;
        let i = find_in_int_repeated_int_map(by_host_id, *hid);
        if i == -1 {
            continue;
        }

        for hcurl_id in &by_host_id[i as usize].value {
            let mut s = String::from(&find_in_int_string_map(hcurl_cache, *hcurl_id));
            if !subpath.is_empty() {
                s.push('/');
                s.push_str(&subpath);
            }
            if file.is_empty() && path_is_dir {
                s.push('/');
            }
            if !file.is_empty() {
                if !s.ends_with('/') {
                    s.push('/');
                }
                s.push_str(file);
            }
            hcurls.push(s);
        }
        result.push((*hid, hcurls));
    }
    result
}

fn trim_to_preferred_protocols(
    hosts_and_urls: &mut Vec<(i64, Vec<String>)>,
    try_protocols: &[&str],
    max: usize,
) {
    let mut result: Vec<(i64, Vec<String>)> = Vec::new();
    let mut count: usize;
    for (host, hcurls) in std::mem::take(hosts_and_urls) {
        let mut url: Vec<String> = Vec::new();
        count = 0;
        for hcurl in hcurls {
            for p in try_protocols {
                let prot = String::from(&format!("{p}:"));
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
        if !url.is_empty() {
            result.push((host, url));
        }
    }
    if !result.is_empty() {
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

struct DoMirrorlist<'a> {
    mirrorlist: &'a MirrorList,
    remote: &'a IpAddr,
    asn_cache: &'a (
        IpLookupTable<Ipv4Addr, String>,
        IpLookupTable<Ipv6Addr, String>,
    ),
    geoip: &'a Reader<std::vec::Vec<u8>>,
    cc: &'a HashMap<String, String>,
    log_file: &'a File,
    minimum: usize,
}

fn do_mirrorlist(req: Request<Body>, p: &mut DoMirrorlist) -> Response<Body> {
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
        Some(q) => q.split('&').collect(),
        _ => Vec::new(),
    };

    // Fill query_params hashmap
    let mut query_params: HashMap<&str, &str> = HashMap::new();
    for param in params {
        let elements: Vec<&str> = param.split('=').collect();
        if elements.len() == 1 {
            query_params.insert(elements[0], "");
        } else {
            query_params.insert(elements[0], elements[1]);
        }
    }

    if !((query_params.contains_key("repo") && query_params.contains_key("arch"))
        || query_params.contains_key("path"))
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
    let mirrorlist_caches = &p.mirrorlist.MirrorListCache;

    if query_params.contains_key("path") {
        let mut path = get_param(&query_params, "path");
        path = path.trim_matches('/').to_string();
        let re = Regex::new(r"/+").unwrap();
        path = re.replace_all(&path, "/").to_string();
        let index = find_in_mirrorlist_cache(mirrorlist_caches, &path);

        header.push_str("# path = ");
        header.push_str(&path);
        header.push(' ');

        if index == -1 {
            // path was a file
            sdir = path.split('/').collect();
            file.push_str(sdir[sdir.len() - 1]);
            dir.push_str(path.trim_end_matches(&file).trim_end_matches('/'));
            let index = find_in_mirrorlist_cache(mirrorlist_caches, &dir);
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
            dir.push_str(cache.directory());
        }
    } else {
        if get_param(&query_params, "repo").contains("source") {
            if query_params.contains_key("arch") {
                query_params.remove(&"arch");
            }
            query_params.insert("arch", "source");
        }
        let repo_redirect_cache = &p.mirrorlist.RepositoryRedirectCache;
        let mut repo =
            find_in_string_string_map(repo_redirect_cache, &get_param(&query_params, "repo"));
        if repo.is_empty() {
            repo = get_param(&query_params, "repo");
        }
        let arch = get_param(&query_params, "arch");
        let _ = write!(header, "# repo = {repo} arch = {arch} ");
        if find_in_string_bool_map(&p.mirrorlist.DisabledRepositoryCache, &repo) {
            return http_response(metalink, "repo disabled".to_string(), StatusCode::OK);
        }
        let key = find_in_string_string_map(
            &p.mirrorlist.RepoArchToDirectoryName,
            &format!("{repo}+{arch}"),
        );
        if key.is_empty() {
            let mut repos: Vec<String> = Vec::new();
            for e in &p.mirrorlist.RepoArchToDirectoryName {
                repos.push(e.key().to_string());
            }
            repos.sort();
            let mut repo_information = String::from(&header);
            repo_information.push_str("error: invalid repo or arch\n");
            repo_information.push_str("# following repositories are available:\n");
            for r in repos {
                let elements: Vec<&str> = r.split('+').collect();
                if elements.len() == 2 {
                    let _ = writeln!(
                        repo_information,
                        "# repo={}&arch={}",
                        elements[0], elements[1]
                    );
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
        let index = find_in_mirrorlist_cache(mirrorlist_caches, &dir);
        if index == -1 {
            *response.body_mut() = Body::from("mirrorlist cache index out of range, you broke it!");
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return response;
        }
        cache = &mirrorlist_caches[index as usize];
    }

    let mut ip_string = get_param(&query_params, "ip");
    if req.headers().contains_key("x-forwarded-for") && ip_string.is_empty() {
        ip_string = String::from(req.headers()["x-forwarded-for"].to_str().unwrap());
        ip_string = String::from(ip_string.rsplit(", ").next().unwrap_or(ip_string.as_str()));
    } else if ip_string.is_empty() {
        ip_string.push_str(&p.remote.to_string());
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
    if !country.is_empty() {
        requested_countries = country.split(',').collect();
        if !requested_countries.is_empty() {
            requested_countries.sort_unstable();
            requested_countries.dedup();
        }
    }

    let mut found_via = String::new();
    let mut mirrors_found = 0;
    let mut netblock_results: Vec<(String, i64)> = Vec::new();
    let mut asn_results: Vec<i64> = Vec::new();
    if requested_countries.is_empty()
        && (!query_params.contains_key("netblock") || get_param(&query_params, "netblock") == "1")
    {
        let hnbc = &p.mirrorlist.HostNetblockCache;
        for hnb in hnbc {
            let net: IpNet = match IpNet::from_str(hnb.key()) {
                Ok(net) => net,
                _ => {
                    let ip = match IpAddr::from_str(hnb.key()) {
                        Ok(ip) => ip,
                        _ => continue,
                    };
                    let mut with_mask = String::from(hnb.key());
                    if ip.is_ipv4() {
                        with_mask.push_str("/32");
                    } else {
                        with_mask.push_str("/128");
                    }
                    IpNet::from_str(&with_mask).unwrap()
                }
            };
            if net.contains(&client_ip) {
                for id in &hnb.value {
                    // Check if the host actually caries the requested content
                    if find_in_int_repeated_int_map(&cache.ByHostId, *id) > 0 {
                        netblock_results.push((String::from(&net.to_string()), *id));
                    }
                }
            }
        }

        if !netblock_results.is_empty() {
            header.push_str("Using preferred netblock ");
            found_via = String::from("netblocks");
        }

        mirrors_found += netblock_results.len();

        // Not enough mirrors where found using the netblock information.
        // Let's check ASN information for matches

        // First find the ASN from the global_netblocks file
        let asn = find_in_ip_tree(p.asn_cache, &client_ip);
        if !asn.1.is_empty() {
            let host_asn_cache = &p.mirrorlist.HostAsnCache;
            let asn_number = asn.1.parse::<i64>().unwrap_or(-1);
            let i = find_in_int_repeated_int_map(host_asn_cache, asn_number);
            if i != -1 {
                for id in &host_asn_cache[i as usize].value {
                    asn_results.push(*id);
                }
            }
        }
        if !asn_results.is_empty() {
            let _ = write!(header, "Using ASN {} ", asn.1);
            mirrors_found += asn_results.len();
            if found_via.is_empty() {
                found_via = String::from("asn");
            }
        }
    }

    info!("mirrors_found after netblock {:#?}", mirrors_found);

    // First check if we assigned this IP to another country
    let mut client_country: String =
        find_in_netblock_country_cache(&p.mirrorlist.NetblockCountryCache, &client_ip);
    if client_country.is_empty() {
        // Do a GeoIP 2 lookup. In the Python implementation
        // this was more complicated as it was doing IPv6, Teredo
        // and IPv4 separately. Not necessary with GeoIP2.
        client_country = match p
            .geoip
            .lookup(client_ip)
            .and_then(|r| r.decode::<geoip2::Country>())
        {
            Ok(Some(country)) => match country.country.iso_code {
                Some(iso) => iso.to_string(),
                None => "N/A".to_string(),
            },
            _ => "N/A".to_string(),
        };
    }

    if query_params.contains_key("repo") && query_params.contains_key("arch") {
        let now = chrono::Utc::now();
        let log_msg = &format!(
            "IP: {}; DATE: {}; COUNTRY: {}; REPO: {}; ARCH: {}\n",
            client_ip,
            &now.format("%Y-%m-%d").to_string(),
            client_country,
            get_param(&query_params, "repo"),
            get_param(&query_params, "arch")
        );
        p.log_file.write_all(log_msg.as_bytes()).unwrap();
        p.log_file.flush().unwrap();
    }

    let mut country_results: Vec<i64> = Vec::new();
    let mut continent_results: Vec<i64> = Vec::new();
    // If the user requested only mirrors for a certain country, this makes
    // sure that no continent or global mirrors are included. Even if the
    // user requested only mirrors for a certain country it will always
    // include the mirrors from the netblock/ASN/Internet2.
    let mut only_country = false;
    if !requested_countries.is_empty() {
        for country in &requested_countries {
            if country.to_uppercase() == "global".to_uppercase() {
                country_results.append(&mut cache.Global.to_vec());
                let ret = do_global(
                    &p.mirrorlist.HostCountryAllowedCache,
                    &mut country_results,
                    client_country.to_string(),
                );
                header.push_str(&ret);
            }
            let ret = do_countrylist(&cache.ByCountry, &mut country_results, country.to_string());
            if !ret.is_empty() {
                header.push_str(&ret);
            }
        }
        if country_results.is_empty() {
            // No mirror in that country found, let's use all countries from the continent
            for country in requested_countries {
                let ret = get_same_continent_hosts(
                    &cache.ByCountry,
                    p.cc,
                    country.to_string(),
                    &mut continent_results,
                );
                if ret.is_empty() {
                    continue;
                }
                header.push_str(&ret);
            }
        }
        if !country_results.is_empty() || !continent_results.is_empty() {
            let hcac = &p.mirrorlist.HostCountryAllowedCache;
            country_results =
                trim_by_client_country(hcac, &mut country_results, client_country.to_string());
            continent_results =
                trim_by_client_country(hcac, &mut continent_results, client_country.to_string());
            mirrors_found += country_results.len() + continent_results.len();
            // If there has been a mirror based on the country specified with country= and/or
            // the corresponding continent, do not any further mirrors to the list.
            // The user has explicitly selected a limited list of mirrors.
            only_country = true;
            if found_via.is_empty() {
                found_via = String::from("country");
            }
        }
    }

    info!("mirrors_found after country {:#?}", mirrors_found);

    let mut geoip_results: Vec<i64> = Vec::new();
    if !only_country {
        // Use GeoIP location do get a country list
        let ret = do_countrylist(
            &cache.ByCountry,
            &mut geoip_results,
            client_country.to_string(),
        );
        if !ret.is_empty() {
            header.push_str(&ret);
        }
        if !geoip_results.is_empty() {
            mirrors_found += geoip_results.len();
            if found_via.is_empty() {
                found_via = String::from("geoip");
            }
        }
    }
    info!("mirrors_found after geoip country {:#?}", mirrors_found);
    if !only_country {
        // Use GeoIP location do get a country on continent list
        let ret = get_same_continent_hosts(
            &cache.ByCountry,
            p.cc,
            client_country.to_string(),
            &mut continent_results,
        );
        if !ret.is_empty() {
            header.push_str(&ret);
            mirrors_found += continent_results.len();
            if found_via.is_empty() {
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
            actual_hosts.push(e.1);
        }

        actual_hosts.extend(&asn_results);
        actual_hosts.extend(&country_results);
        actual_hosts.extend(&geoip_results);
        actual_hosts.extend(&continent_results);

        let actual_hosts: Vec<_> = actual_hosts.into_iter().unique().collect();

        let mut hosts_and_urls = append_path(
            &actual_hosts,
            cache,
            &p.mirrorlist.HCUrlCache,
            &file,
            path_is_dir,
        );
        if query_params.contains_key("protocol") {
            let protocols = get_param(&query_params, "protocol");
            let mut try_protocols: Vec<&str> = protocols.split(',').collect();
            if !try_protocols.is_empty() {
                try_protocols.sort_unstable();
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
    if mirrors_found < p.minimum && !only_country {
        // Use mirrors from everywhere
        global_results = cache.Global.to_vec();
        let ret = do_global(
            &p.mirrorlist.HostCountryAllowedCache,
            &mut global_results,
            client_country,
        );
        header.push_str(&ret);
        if found_via.is_empty() || mirrors_found == 0 {
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
    netblock_results.shuffle(&mut rand::rng());
    netblock_results.sort_by_key(|k| IpNet::from_str(&k.0).unwrap().prefix_len());
    netblock_results.reverse();

    for e in netblock_results {
        all_hosts.push(e.1);
    }

    // Just shuffle
    asn_results.shuffle(&mut rand::rng());
    all_hosts.append(&mut asn_results);

    {
        let hbc = &p.mirrorlist.HostBandwidthCache;
        // Weighted shuffle by bandwidth
        weighted_shuffle(&mut country_results, hbc, &mut all_hosts);
        weighted_shuffle(&mut geoip_results, hbc, &mut all_hosts);
        weighted_shuffle(&mut continent_results, hbc, &mut all_hosts);
        weighted_shuffle(&mut global_results, hbc, &mut all_hosts);
    }
    let all_hosts: Vec<_> = all_hosts.into_iter().unique().collect();

    let mut hosts_and_urls = append_path(
        &all_hosts,
        cache,
        &p.mirrorlist.HCUrlCache,
        &file,
        path_is_dir,
    );

    let mut protocols_trimmed = false;
    if query_params.contains_key("protocol") {
        let protocols = get_param(&query_params, "protocol");
        let mut try_protocols: Vec<&str> = protocols.split(',').collect();
        if !try_protocols.is_empty() {
            try_protocols.sort_unstable();
            try_protocols.dedup();
        }
        trim_to_preferred_protocols(&mut hosts_and_urls, &try_protocols, try_protocols.len());
        header.push_str("protocol = ");
        header.push_str(&protocols);
        protocols_trimmed = true;
    }

    if query_params.contains_key("time") {
        let _ = write!(
            header,
            "\n# database creation time: {}",
            &p.mirrorlist.Time.unwrap(),
        );
    }

    if metalink {
        let (code, doc) = do_metalink(cache, p.mirrorlist, dir, file, &hosts_and_urls);
        *response.status_mut() = code;
        *response.body_mut() = Body::from(doc);
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/metalink+xml"),
        );
    } else {
        if query_params.contains_key("redirect") {
            trim_to_preferred_protocols(&mut hosts_and_urls, &["https", "http"], 1);
            protocols_trimmed = true;
        }
        if !protocols_trimmed {
            trim_to_preferred_protocols(&mut hosts_and_urls, &["https", "http", "ftp"], 1);
        }
        if query_params.contains_key("redirect") {
            let mut redirect = String::new();
            if !hosts_and_urls.is_empty() {
                for (_, urls) in hosts_and_urls {
                    for u in urls {
                        if u.starts_with("http") {
                            redirect += &u;
                            break;
                        }
                    }
                    if !redirect.is_empty() {
                        break;
                    }
                }
            }

            if redirect.is_empty() {
                *response.status_mut() = StatusCode::NOT_FOUND;
            } else {
                *response.status_mut() = StatusCode::FOUND;
                response
                    .headers_mut()
                    .insert(LOCATION, HeaderValue::from_str(&redirect).unwrap());
            }
        } else {
            let mut answer = header;
            answer.push('\n');
            for (_, urls) in hosts_and_urls {
                for u in urls {
                    answer.push_str(&u);
                    answer.push('\n');
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
    if fd.TimeStamp() != 0 {
        result.push_str(&indent);
        let _ = writeln!(result, " <mm0:timestamp>{}</mm0:timestamp>", fd.TimeStamp());
    }
    if fd.Size() != 0 {
        result.push_str(&indent);
        let _ = writeln!(result, " <size>{}</size>", fd.Size());
    }
    result.push_str(&indent);
    result.push_str(" <verification>\n");
    if !fd.MD5().is_empty() {
        result.push_str(&indent);
        let _ = writeln!(result, "  <hash type=\"md5\">{}</hash>", fd.MD5());
    }
    if !fd.SHA1().is_empty() {
        result.push_str(&indent);
        let _ = writeln!(result, "  <hash type=\"sha1\">{}</hash>", fd.SHA1());
    }
    if !fd.SHA256().is_empty() {
        result.push_str(&indent);
        let _ = writeln!(result, "  <hash type=\"sha256\">{}</hash>", fd.SHA256());
    }
    if !fd.SHA512().is_empty() {
        result.push_str(&indent);
        let _ = writeln!(result, "  <hash type=\"sha512\">{}</hash>", fd.SHA512());
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
    hosts_and_urls: &[(i64, Vec<String>)],
) -> (hyper::StatusCode, String) {
    let mut preference = 100;
    let fdcdc_index =
        find_in_file_details_cache_directory_cache(&mirrorlist.FileDetailsCache, &dir);
    if fdcdc_index == -1 {
        return (
            StatusCode::NOT_FOUND,
            metalink_failuredoc(format!("{dir}/{file} not found or has not metalink")),
        );
    }
    let fdcf = &mirrorlist.FileDetailsCache[fdcdc_index as usize]
        .FileDetailsCacheFiles
        .to_vec();
    let mut wrong_file = true;
    for e in fdcf {
        if e.filename() == file {
            wrong_file = false;
        }
    }
    if wrong_file || fdcf.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            metalink_failuredoc(format!("{dir}/{file} not found or has not metalink")),
        );
    }
    let mut doc = metalink_header();
    doc.push_str(" <files>\n");
    let _ = writeln!(doc, "  <file name=\"{file}\">");
    let mut count = 0;
    for e in fdcf {
        if e.filename() != file {
            continue;
        }
        for fd in &e.FileDetails {
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
        for i in &cache.Global {
            if i == host {
                private = String::new();
            }
        }
        for url in hcurls {
            let protocol: Vec<&str> = url.split(':').collect();
            if protocol.is_empty() {
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
            doc += &find_in_int_string_map(&mirrorlist.HostCountryCache, *host).to_uppercase();
            let _ = write!(doc, "\" preference=\"{preference}\"{private}>");
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
        let e: Vec<&str> = l.split(',').collect();
        // The country_continent CSV file uses 2 characters for all countries
        // and all continents.
        if e[0].len() != 2 {
            continue;
        }
        let mut continent = find_in_string_string_map(ccrc, &String::from(e[0]));
        if continent.is_empty() {
            continent = String::from(e[1]);
        }
        result.insert(String::from(e[0]), continent);
    }
    result
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {program} [options]");
    print!("{}", opts.usage(&brief));
}

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    // This is the minimum number of mirrors which should be returned
    let mut minimum: usize = 5;
    let mut geoip2_db = String::from("/usr/share/GeoIP/GeoLite2-Country.mmdb");
    let mut cache_file = String::from("/var/lib/mirrormanager/mirrorlist_cache.proto");
    let mut global_netblocks = String::from("/var/lib/mirrormanager/global_netblocks.txt");
    let mut cccsv = String::from("/var/lib/mirrormanager/country_continent.csv");
    let mut logfile = String::from("/var/log/mirrormanager/mirrorlist.log");
    let mut listen = String::from("127.0.0.1");
    let mut port: usize = 3000;

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optmulti(
        "",
        "listen",
        &format!("IP address to listen to ({listen})"),
        "ADDRESS",
    );
    opts.optmulti(
        "",
        "port",
        &format!("TCP port to listen to ({port})"),
        "PORT",
    );
    opts.optmulti(
        "m",
        "minimum",
        &format!("minimum number of mirrors to return ({minimum})"),
        "NUMBER",
    );
    opts.optmulti(
        "c",
        "cache",
        &format!("protobuf cache file location ({cache_file})"),
        "CACHE",
    );
    opts.optmulti(
        "i",
        "internet2_netblocks",
        "internet2 netblocks file location (deprecated - unused)",
        "CACHE",
    );
    opts.optmulti(
        "g",
        "global_netblocks",
        &format!("global netblocks file location ({global_netblocks})"),
        "CACHE",
    );
    opts.optmulti("l", "log", &format!("logfile ({logfile})"), "LOG");
    opts.optmulti(
        "",
        "cccsv",
        &format!("country continent csv file ({cccsv})"),
        "CSV",
    );
    opts.optmulti(
        "",
        "geoip",
        &format!("GeoIP country mmdb ({geoip2_db})"),
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
                println!("Error parsing minimum number of mirrors. Defaulting to {minimum}");
                minimum
            }
        };
    }

    if matches.opt_present("port") {
        port = match matches.opt_strs("port")[matches.opt_count("port") - 1].parse::<usize>() {
            Ok(po) => po,
            _ => {
                println!("Error parsing port. Defaulting to {port}");
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
    let mut file = match File::open(Path::new(&cache_file)) {
        Ok(f) => f,
        Err(e) => {
            error!("Opening {} failed: {}", &cache_file, e);
            process::exit(1)
        }
    };
    let mirrorlist: Arc<MirrorList> =
        Arc::new(match protobuf::Message::parse_from_reader(&mut file) {
            Ok(f) => f,
            Err(e) => {
                error!("Parsing {} failed: {}", &cache_file, e);
                process::exit(1)
            }
        });

    if let Some(t) = chrono::DateTime::from_timestamp(mirrorlist.Time.unwrap() as i64, 0) {
        info!(
            "Database creation time {} ({}) ",
            t,
            &mirrorlist.Time.unwrap()
        );
    }

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

    if asn_cache.0.is_empty() {
        error!("Creating ASN cache failed. Exiting!");
        process::exit(1);
    }

    info!("Loading country-continents");
    let cc_redirect = Arc::new(setup_continents(
        &cccsv,
        &mirrorlist.CountryContinentRedirectCache,
    ));

    if cc_redirect.is_empty() {
        error!("Parsing country continent data failed. Exiting!");
        process::exit(1);
    }

    let addr = String::from(&format!("{listen}:{port}"));
    let addr: SocketAddr = addr.parse().expect("Unable to parse address!");

    let new_service = make_service_fn(move |socket: &AddrStream| {
        let remote_addr = socket.remote_addr();
        let val = mirrorlist.clone();
        let asn = asn_cache.clone();
        let geoip2 = geoip_reader.clone();
        let cc = cc_redirect.clone();
        let lf = log_file.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let response = do_mirrorlist(
                    req,
                    &mut DoMirrorlist {
                        mirrorlist: &val,
                        remote: &remote_addr.ip(),
                        asn_cache: &asn,
                        geoip: &geoip2,
                        cc: &cc,
                        log_file: &lf,
                        minimum,
                    },
                );
                async move { Ok::<_, Infallible>(response) }
            }))
        }
    });

    let server = Server::bind(&addr).serve(new_service);

    println!("Listening on http://{addr}");

    if let Err(err) = server.await {
        eprintln!("server error: {err}");
    }
}

#[cfg(test)]
mod mirrorlist_server_test;
