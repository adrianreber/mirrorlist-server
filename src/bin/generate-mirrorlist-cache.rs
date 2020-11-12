#![deny(warnings)]
#[macro_use]
extern crate diesel;
extern crate chrono;
extern crate dns_lookup;
extern crate dotenv;
extern crate indicatif;

pub mod db;
pub mod lib;

use chrono::{DateTime, Utc};
use console::style;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use dns_lookup::lookup_host;
use getopts::Options;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use ipnetwork::IpNetwork;
use lib::common::{
    find_in_file_details_cache_directory_cache, find_in_file_details_cache_files_cache,
    find_in_int_repeated_int_map, find_in_int_repeated_string_map, find_in_string_repeated_int_map,
};
use lib::protos::mirrormanager::{
    FileDetailsCacheDirectoryType, FileDetailsCacheFilesType, FileDetailsType, IntIntMap,
    IntRepeatedIntMap, IntRepeatedStringMap, IntStringMap, MirrorList, MirrorListCacheType,
    StringBoolMap, StringRepeatedIntMap, StringStringMap,
};
use protobuf::error::ProtobufError;
use protobuf::{CodedOutputStream, Message, RepeatedField};
use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
use std::fs::File;
use std::net::IpAddr;
use std::process;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

/* This implementation ignores 'directory_exclusive_host' as it has never been used
 * and it cannot be set from MirrorManager2.
 *
 * 'location' is also ignored as MirrorManager2 did never support that.
 *
 * 'ordered_mirrorlist' is also ignored as the Rust based mirrorlist-server does not evaluate it.
 * */

const STEPS: i32 = 18;
static CALL_COUNT: AtomicUsize = AtomicUsize::new(1);
static DEBUG: AtomicUsize = AtomicUsize::new(0);

fn pg_conn(conf: String) -> PgConnection {
    dotenv::from_filename(&conf).ok();

    let db_url = match env::var("DB_URL") {
        Ok(d) => d,
        _ => {
            println!("Error reading configuration file {}", conf);
            process::exit(1);
        }
    };
    PgConnection::establish(&db_url).expect("Error connecting to database")
}

fn print_step(msg: String) {
    let d = DEBUG.load(Ordering::SeqCst);
    let s = CALL_COUNT.load(Ordering::SeqCst);
    CALL_COUNT.fetch_add(1, Ordering::SeqCst);
    if d == 0 {
        return;
    }
    println!(
        " Step {}: {}",
        style(format!("[{}/{}]", s, STEPS)).bold().dim(),
        msg
    );
}

fn get_netblocks(c: &PgConnection) -> Vec<(i32, String)> {
    use db::schema::host_netblock::dsl::*;
    let query = host_netblock.select((host_id, netblock));
    let debug = diesel::debug_query::<diesel::pg::Pg, _>(&query);
    print_step(debug.to_string());
    query
        .load::<(i32, String)>(c)
        .expect("Error loading host ids")
}

fn get_host_country_allowed(c: &PgConnection) -> Vec<(i32, String)> {
    use db::schema::host_country_allowed::dsl::*;
    let query = host_country_allowed.select((host_id, country));
    let debug = diesel::debug_query::<diesel::pg::Pg, _>(&query);
    print_step(debug.to_string());
    query
        .load::<(i32, String)>(c)
        .expect("Error loading host ids")
}

type Directory = (i32, String);

fn get_directories(c: &PgConnection) -> Vec<Directory> {
    use db::schema::directory::dsl::*;
    let query = directory.select((id, name));
    let debug = diesel::debug_query::<diesel::pg::Pg, _>(&query);
    print_step(debug.to_string());
    query
        .load::<Directory>(c)
        .expect("Error loading directories")
}

type Repository = (
    Option<String>,
    Option<i32>,
    Option<i32>,
    Option<i32>,
    Option<i32>,
    bool,
);

fn get_repositories(c: &PgConnection) -> Vec<Repository> {
    use db::schema::repository::dsl::*;
    let query = repository
        .select((
            prefix,
            category_id,
            version_id,
            arch_id,
            directory_id,
            disabled,
        ))
        .filter(directory_id.is_not_null())
        .filter(version_id.is_not_null())
        .filter(arch_id.is_not_null());
    let debug = diesel::debug_query::<diesel::pg::Pg, _>(&query);
    print_step(debug.to_string());
    query
        .load::<Repository>(c)
        .expect("Error loading repositories")
}

type FileDetail = (
    i32,
    String,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn get_file_details(c: &PgConnection) -> Vec<FileDetail> {
    use db::schema::file_detail::dsl::*;
    let query = file_detail
        .select((
            directory_id,
            filename,
            timestamp,
            size,
            sha1,
            md5,
            sha256,
            sha512,
        ))
        .order(timestamp.desc());
    let debug = diesel::debug_query::<diesel::pg::Pg, _>(&query);
    print_step(debug.to_string());
    query
        .load::<FileDetail>(c)
        .expect("Error loading file details")
}

fn get_host_categories(c: &PgConnection) -> Vec<(i32, Option<i32>, Option<i32>, bool)> {
    use db::schema::host_category::dsl::*;
    let query = host_category.select((id, host_id, category_id, always_up2date));
    let debug = diesel::debug_query::<diesel::pg::Pg, _>(&query);
    print_step(debug.to_string());
    query
        .load::<(i32, Option<i32>, Option<i32>, bool)>(c)
        .expect("Error loading host categories")
}

fn get_arches(c: &PgConnection) -> Vec<(i32, String)> {
    use db::schema::arch::dsl::*;
    let query = arch.select((id, name));
    let debug = diesel::debug_query::<diesel::pg::Pg, _>(&query);
    print_step(debug.to_string());
    query
        .load::<(i32, String)>(c)
        .expect("Error loading arches")
}

fn get_category_directories(c: &PgConnection) -> Vec<(i32, i32)> {
    use db::schema::category_directory::dsl::*;
    let query = category_directory.select((category_id, directory_id));
    let debug = diesel::debug_query::<diesel::pg::Pg, _>(&query);
    print_step(debug.to_string());
    query
        .load::<(i32, i32)>(c)
        .expect("Error loading category directories")
}

fn get_categories(c: &PgConnection) -> Vec<(i32, i32)> {
    use db::schema::category::dsl::*;
    let query = category.select((id, topdir_id));
    let debug = diesel::debug_query::<diesel::pg::Pg, _>(&query);
    print_step(debug.to_string());
    query
        .load::<(i32, i32)>(c)
        .expect("Error loading categories")
}

fn get_netblock_countries(c: &PgConnection) -> Vec<(String, String)> {
    use db::schema::netblock_country::dsl::*;
    let query = netblock_country.select((netblock, country));
    let debug = diesel::debug_query::<diesel::pg::Pg, _>(&query);
    print_step(debug.to_string());
    query
        .load::<(String, String)>(c)
        .expect("Error loading country continent redirects")
}

fn get_country_continent_redirects(c: &PgConnection) -> Vec<(String, String)> {
    use db::schema::country_continent_redirect::dsl::*;
    let query = country_continent_redirect.select((country, continent));
    let debug = diesel::debug_query::<diesel::pg::Pg, _>(&query);
    print_step(debug.to_string());
    query
        .load::<(String, String)>(c)
        .expect("Error loading country continent redirects")
}

fn get_repository_redirects(c: &PgConnection) -> Vec<(String, Option<String>)> {
    use db::schema::repository_redirect::dsl::*;
    let query = repository_redirect.select((from_repo, to_repo));
    let debug = diesel::debug_query::<diesel::pg::Pg, _>(&query);
    print_step(debug.to_string());
    query
        .load::<(String, Option<String>)>(c)
        .expect("Error loading repository redirects")
}

fn get_host_category_urls(c: &PgConnection) -> Vec<(i32, i32, String)> {
    use db::schema::host_category_url::dsl::*;
    let query = host_category_url
        .select((id, host_category_id, url))
        .filter(private.eq(false));
    let debug = diesel::debug_query::<diesel::pg::Pg, _>(&query);
    print_step(debug.to_string());
    query
        .load::<(i32, i32, String)>(c)
        .expect("Error loading host category urls")
}

fn get_host_category_dirs(c: &PgConnection) -> Vec<(i32, i32)> {
    use db::schema::host_category_dir::dsl::*;
    let query = host_category_dir
        .select((host_category_id, directory_id))
        .filter(up2date.eq(true));
    let debug = diesel::debug_query::<diesel::pg::Pg, _>(&query);
    print_step(debug.to_string());
    query
        .load::<(i32, i32)>(c)
        .expect("Error loading host category dirs")
}

fn get_element(host: i32, element: &Vec<(i32, String)>) -> Vec<String> {
    let mut n: Vec<String> = Vec::new();
    for e in element {
        if e.0 == host {
            n.push(String::from(&e.1));
        }
    }
    n
}

fn get_host(host: i32, hosts: &Vec<Host>) -> Host {
    for h in hosts {
        if h.0 == host {
            return h.clone();
        }
    }
    let mut host = hosts[0].clone();
    host.0 = -1;
    host
}

/* id, site.user_active, user_active, admin_active, bandwidth, country, asn_clients,
 * asn (can be NULL), max_connections, site.admin_active, private, site.private, internet2,
 * internet2_clients, name */
type Host = (
    i32,
    bool,
    bool,
    bool,
    i32,
    Option<String>,
    bool,
    Option<i32>,
    i32,
    bool,
    bool,
    bool,
    bool,
    bool,
    String,
);

fn get_hosts(c: &PgConnection) -> Vec<Host> {
    use db::schema::host::dsl::*;
    use db::schema::site::dsl::*;

    let query = host.inner_join(site).select((
        db::schema::host::dsl::id,          /* 0 */
        db::schema::site::dsl::user_active, /* 1 */
        db::schema::host::dsl::user_active,
        db::schema::host::dsl::admin_active,
        db::schema::host::dsl::bandwidth_int,
        db::schema::host::dsl::country, /* 5 */
        db::schema::host::dsl::asn_clients,
        db::schema::host::dsl::asn,
        db::schema::host::dsl::max_connections,
        db::schema::site::dsl::admin_active,
        db::schema::host::dsl::private, /* 10 */
        db::schema::site::dsl::private,
        db::schema::host::dsl::internet2,
        db::schema::host::dsl::internet2_clients, /* 13 */
        db::schema::host::dsl::name,              /* 14 */
    ));
    let debug = diesel::debug_query::<diesel::pg::Pg, _>(&query);
    print_step(debug.to_string());
    query.load::<Host>(c).expect("Error loading host ids")
}

fn is_host_active(h: Host) -> bool {
    /* site.user_active, user_active, admin_active, site.admin_active
     * The python implementation did not check site.admin_active. */
    h.1 && h.2 && h.3 && h.9
}

fn is_host_private(h: Host) -> bool {
    h.10 || h.11
}

fn parse_ip(input: String, host: String) -> Result<Vec<IpNet>, String> {
    /* This function is unnecessarily complicated as it has
     * to deal with the free form input from users. */
    let ip_string = String::from(input.to_string().trim());
    let net = match IpNet::from_str(&ip_string) {
        Ok(net) => net,
        _ => {
            let ip = match IpAddr::from_str(&ip_string) {
                Ok(ip) => ip,
                _ => {
                    /* If IpAddr was not able to parse it, it is either
                     * an IP address with a netmask 1.2.3.4/255.255.255.248
                     * or a DNS name. If it can be split at '/' it is an IP
                     * with a netmask, else try to resolve it. */
                    let split_ip: Vec<&str> = ip_string.split("/").collect();
                    if split_ip.len() != 2 {
                        /* Probably DNS name */
                        let ips = lookup_host(&ip_string);
                        if ips.is_err() {
                            println!("DNS resolve error {} for host {}\n", ip_string, host);
                            return Err("Parse Error".to_string());
                        }
                        let mut result: Vec<IpNet> = Vec::new();
                        for ip in ips.unwrap() {
                            let n: IpNet = match ip {
                                IpAddr::V4(ip4) => IpNet::V4(Ipv4Net::from(ip4)),
                                IpAddr::V6(ip6) => IpNet::V6(Ipv6Net::from(ip6)),
                            };
                            result.push(n);
                        }

                        return Ok(result);
                    }
                    let prefix: Result<std::net::IpAddr, std::net::AddrParseError> =
                        IpAddr::from_str(split_ip[0]);
                    let suffix: Result<std::net::IpAddr, std::net::AddrParseError> =
                        IpAddr::from_str(split_ip[1]);
                    if prefix.is_err() && suffix.is_err() {
                        return Err("Parse Error".to_string());
                    }
                    /* There is already IpNet imported but it seems only IpNetwork
                     * can parse x.x.x.x/x.x.x.x */
                    let ip_network = IpNetwork::with_netmask(prefix.unwrap(), suffix.unwrap());
                    if ip_network.is_err() {
                        /* Parsing failed. Ignore it. */
                        return Err("Parse Error".to_string());
                    }
                    let mut with_mask = String::from(ip_network.clone().unwrap().ip().to_string());
                    with_mask.push_str("/");
                    let netmask = String::from(ip_network.unwrap().prefix().to_string());
                    with_mask.push_str(&netmask);
                    let n = IpNet::from_str(&with_mask);
                    if n.is_err() {
                        /* Parsing failed. Ignore it. */
                        return Err("Parse Error".to_string());
                    }
                    return Ok(vec![n.unwrap()]);
                }
            };
            let mut with_mask = String::from(&ip_string);
            if ip.is_ipv4() {
                with_mask.push_str("/32");
            } else {
                with_mask.push_str("/128");
            }
            IpNet::from_str(&with_mask).unwrap()
        }
    };
    Ok(vec![net])
}

/* HostBandwidthCache */
fn get_hbc(hosts: &Vec<Host>) -> RepeatedField<IntIntMap> {
    let mut hbc: RepeatedField<IntIntMap> = RepeatedField::new();

    for h in hosts {
        let mut hb = IntIntMap::new();
        let mut i = h.4;
        if i < 1 {
            i = 1;
        } else if i > 10000 {
            /* Allow a maximum of 10Gbit/s. */
            i = 10000;
        }
        hb.set_key(h.0.into());
        hb.set_value(i.into());
        hbc.push(hb);
    }

    hbc
}

/* HostMaxConnectionCache */
fn get_hmcc(hosts: &Vec<Host>) -> RepeatedField<IntIntMap> {
    let mut hmcc: RepeatedField<IntIntMap> = RepeatedField::new();

    for h in hosts {
        let mut hmc = IntIntMap::new();
        hmc.set_key(h.0.into());
        hmc.set_value(h.8.into());
        hmcc.push(hmc);
    }

    hmcc
}

/* HostCountryCache */
fn get_hcc(hosts: &Vec<Host>) -> RepeatedField<IntStringMap> {
    let mut hcc: RepeatedField<IntStringMap> = RepeatedField::new();

    for h in hosts {
        let mut hc = IntStringMap::new();
        if h.5.is_none() {
            continue;
        }
        hc.set_key(h.0.into());
        hc.set_value(h.5.as_ref().unwrap().to_uppercase());
        hcc.push(hc);
    }

    hcc
}

/* HostAsnCache */
fn get_hac(hosts: &Vec<Host>) -> RepeatedField<IntRepeatedIntMap> {
    let mut hac: RepeatedField<IntRepeatedIntMap> = RepeatedField::new();

    for h in hosts {
        if !h.6 {
            continue;
        }
        if h.7.is_none() {
            continue;
        }
        let i = find_in_int_repeated_int_map(&hac, h.7.unwrap().into());
        if i != -1 {
            let val = &mut hac[i as usize].mut_value();
            val.push(h.0.into());
        } else {
            let mut hc = IntRepeatedIntMap::new();
            hc.set_key(h.7.unwrap().into());
            let val = hc.mut_value();
            val.push(h.0.into());
            hac.push(hc);
        }
    }

    hac
}

/* HostCountryAllowedCache */
fn get_hcac(c: &PgConnection, hosts: &Vec<Host>) -> RepeatedField<IntRepeatedStringMap> {
    let mut hcac: RepeatedField<IntRepeatedStringMap> = RepeatedField::new();

    let hcac_raw = get_host_country_allowed(c);

    for h in hosts {
        if !is_host_active(h.clone()) {
            continue;
        }
        let element = get_element(h.0, &hcac_raw);
        if element.len() < 1 {
            continue;
        }

        let i = find_in_int_repeated_string_map(&hcac, h.0.into());
        if i != -1 {
            let val = &mut hcac[i as usize].mut_value();
            for e in element {
                val.push(e.to_uppercase());
            }
        } else {
            let mut hca = IntRepeatedStringMap::new();
            hca.set_key(h.0.into());
            let val = hca.mut_value();
            for e in element {
                val.push(e.to_uppercase());
            }
            hcac.push(hca);
        }
    }

    hcac
}

/* HCUrlCache */
fn get_hcurlc(host_category_urls: &Vec<(i32, i32, String)>) -> RepeatedField<IntStringMap> {
    let mut hcurl: RepeatedField<IntStringMap> = RepeatedField::new();

    for hcu in host_category_urls {
        let mut hc_url = IntStringMap::new();
        hc_url.set_key(hcu.0.into());
        hc_url.set_value(hcu.2.clone());
        hcurl.push(hc_url);
    }

    hcurl
}

/* HostNetBlockCache */
fn get_hnbc(c: &PgConnection, hosts: &Vec<Host>) -> RepeatedField<StringRepeatedIntMap> {
    let mut hnbc: RepeatedField<StringRepeatedIntMap> = RepeatedField::new();
    let netblocks_and_hosts = get_netblocks(&c);
    let debug = DEBUG.load(Ordering::SeqCst);

    CALL_COUNT.fetch_add(1, Ordering::SeqCst);
    let pb = ProgressBar::new(hosts.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                " Resolving hosts [{elapsed_precise}] {wide_bar:.cyan/blue} {pos:>7}/{len:7} {msg}",
            )
            .progress_chars("##-"),
    );
    if debug == 0 {
        pb.set_draw_target(ProgressDrawTarget::hidden());
    }
    for h in hosts {
        pb.inc(1);
        if !is_host_active(h.clone()) {
            continue;
        }
        let nb = get_element(h.0, &netblocks_and_hosts);

        for n in &nb {
            let net = match parse_ip(n.to_string(), h.14.clone()) {
                Ok(net) => net,
                _ => continue,
            };

            for key in net {
                let i = find_in_string_repeated_int_map(&hnbc, &key.to_string());
                if i != -1 {
                    let val = &mut hnbc[i as usize].mut_value();
                    val.push(h.0.into());
                } else {
                    let mut netblock_cache = StringRepeatedIntMap::new();
                    netblock_cache.set_key(key.to_string());
                    let val = netblock_cache.mut_value();
                    val.push(h.0.into());
                    hnbc.push(netblock_cache);
                }
            }
        }
    }
    pb.finish_with_message("done");

    hnbc
}

/* RepoArchToDirectoryName */
fn get_ratdn(
    c: &PgConnection,
    directories: &Vec<Directory>,
    repositories: &Vec<Repository>,
) -> RepeatedField<StringStringMap> {
    let mut ratdn: RepeatedField<StringStringMap> = RepeatedField::new();

    let arches = get_arches(c);

    for d in directories {
        let mut found_repos: Vec<Repository> = Vec::new();
        for r in repositories {
            if r.0.is_none() || r.3.is_none() || r.4.is_none() {
                continue;
            }
            if r.0.as_ref().unwrap().len() == 0 {
                continue;
            }
            if r.4.unwrap() == d.0 {
                found_repos.push(r.clone());
            }
        }

        if found_repos.len() < 1 {
            continue;
        }

        for r in found_repos {
            let mut key = String::new();
            key.push_str(r.0.as_ref().unwrap());
            key.push_str("+");
            let mut a_id: i32 = -1;
            let mut i: i32 = -1;
            for a in &arches {
                i += 1;
                if r.3.unwrap() == a.0 {
                    a_id = i;
                    break;
                }
            }
            if a_id == -1 {
                continue;
            }
            key.push_str(&arches[a_id as usize].1);

            let mut repo = StringStringMap::new();

            repo.set_key(key);
            repo.set_value(d.1.clone());
            ratdn.push(repo);
        }
    }

    ratdn
}

/* MirrorListCache */
fn get_mlc(
    c: &PgConnection,
    hosts: &Vec<Host>,
    directories: &Vec<Directory>,
    host_category_urls: &Vec<(i32, i32, String)>,
) -> (
    RepeatedField<MirrorListCacheType>,
    RepeatedField<FileDetailsCacheDirectoryType>,
) {
    let mut mlc: RepeatedField<MirrorListCacheType> = RepeatedField::new();
    let mut fdcdc: RepeatedField<FileDetailsCacheDirectoryType> = RepeatedField::new();

    let categories = get_categories(c);
    let host_categories = get_host_categories(c);
    let category_directories = get_category_directories(c);
    let host_category_dirs = get_host_category_dirs(c);
    let file_details = get_file_details(c);

    // HashMap<category_id, top_dir_len>
    let mut topdir_hash: HashMap<i32, i32> = HashMap::new();
    // HashMap<category_id, Vec<hostid>>
    let mut host_cat_hash: HashMap<i32, Vec<(i64, i64)>> = HashMap::new();
    // HashMap<category_id, always_up2date>
    let mut host_cat_id_hash: HashMap<i32, bool> = HashMap::new();
    // HashMap<host_category_id, Vec<host_category_url_id>>
    let mut hcurl_cat_url_id_hash: HashMap<i64, Vec<i64>> = HashMap::new();
    // HashMap<host_category_url_id, url>
    let mut hcurl_url_id_hash: HashMap<i64, String> = HashMap::new();
    // HashMap<directory_id, Vec<hc_id>
    let mut hcdir_hc_id_hash: HashMap<i32, Vec<i32>> = HashMap::new();

    for hcdir in host_category_dirs {
        let key = hcdir.1;
        let hc_id = hcdir.0;

        let val: &mut Vec<i32> = match hcdir_hc_id_hash.get_mut(&key) {
            Some(v) => &mut *v,
            None => {
                hcdir_hc_id_hash.insert(key, Vec::new());
                &mut *hcdir_hc_id_hash.get_mut(&key).unwrap()
            }
        };
        val.push(hc_id);
    }

    for hcurl in host_category_urls {
        let key: i64 = hcurl.1.into();
        let id: i64 = hcurl.0.into();
        let val: &mut Vec<i64> = match hcurl_cat_url_id_hash.get_mut(&key) {
            Some(v) => &mut *v,
            None => {
                hcurl_cat_url_id_hash.insert(key, Vec::new());
                &mut *hcurl_cat_url_id_hash.get_mut(&key).unwrap()
            }
        };
        val.push(id);
        hcurl_url_id_hash.insert(id, hcurl.2.clone());
    }

    for c in &categories {
        for d in directories {
            if c.1 == d.0 {
                topdir_hash.insert(c.0, d.1.len().try_into().unwrap());
            }
        }
    }

    for hc in &host_categories {
        let key = match hc.2 {
            Some(k) => k,
            _ => continue,
        };
        let id = match hc.1 {
            Some(i) => i,
            _ => continue,
        };
        let val: &mut Vec<(i64, i64)> = match host_cat_hash.get_mut(&key) {
            Some(v) => &mut *v,
            None => {
                host_cat_hash.insert(key, Vec::new());
                &mut *host_cat_hash.get_mut(&key).unwrap()
            }
        };
        val.push((id.into(), hc.0.into()));
        host_cat_id_hash.insert(id.into(), hc.3);
    }

    let debug = DEBUG.load(Ordering::SeqCst);
    CALL_COUNT.fetch_add(1, Ordering::SeqCst);

    let pb = ProgressBar::new(directories.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template(" Looping over directories [{elapsed_precise}] {wide_bar:.cyan/blue} {pos:>7}/{len:7} {msg}")
        .progress_chars("##-"));
    if debug == 0 {
        pb.set_draw_target(ProgressDrawTarget::hidden());
    }
    let mut d_counter = 0;
    for d in directories {
        d_counter += 1;
        if d_counter % 100 == 0 {
            pb.inc(100);
        }

        for fd in &file_details {
            if fd.0 == d.0 {
                let mut i = find_in_file_details_cache_directory_cache(&fdcdc, &d.1);
                if i == -1 {
                    let mut tmp = FileDetailsCacheDirectoryType::new();
                    tmp.set_directory(d.1.clone());
                    fdcdc.push(tmp.clone());
                    i = find_in_file_details_cache_directory_cache(&fdcdc, &d.1);
                }
                let f: &mut FileDetailsCacheDirectoryType = &mut fdcdc[i as usize];
                let fdcfc = f.mut_FileDetailsCacheFiles();
                i = find_in_file_details_cache_files_cache(&fdcfc, &fd.1);
                if i == -1 {
                    let mut tmp = FileDetailsCacheFilesType::new();
                    tmp.set_filename(fd.1.clone());
                    fdcfc.push(tmp.clone());
                    i = find_in_file_details_cache_files_cache(&fdcfc, &fd.1);
                }
                let fdcf: &mut FileDetailsCacheFilesType = &mut fdcfc[i as usize];
                let fdc = fdcf.mut_FileDetails();
                let mut file_detail_type = FileDetailsType::new();
                if fd.2.is_none() {
                    file_detail_type.set_TimeStamp(0);
                } else {
                    file_detail_type.set_TimeStamp(fd.2.unwrap().try_into().unwrap());
                }
                if fd.3.is_none() {
                    file_detail_type.set_Size(0);
                } else {
                    file_detail_type.set_Size(fd.3.unwrap().try_into().unwrap());
                }
                if !fd.4.is_none() {
                    file_detail_type.set_SHA1(fd.4.as_ref().unwrap().clone());
                }
                if !fd.5.is_none() {
                    file_detail_type.set_MD5(fd.5.as_ref().unwrap().clone());
                }
                if !fd.6.is_none() {
                    file_detail_type.set_SHA256(fd.6.as_ref().unwrap().clone());
                }
                if !fd.7.is_none() {
                    file_detail_type.set_SHA512(fd.7.as_ref().unwrap().clone());
                }
                fdc.push(file_detail_type);
            }
        }

        // Check if this directory belongs to a category
        let mut category_id: i32 = -1;
        for cd in &category_directories {
            if cd.1 == d.0 {
                category_id = cd.0;
                break;
            }
        }
        if category_id == -1 {
            continue;
        }

        let mut ml = MirrorListCacheType::new();
        ml.set_directory(d.1.clone());
        /* This only works as long as there are not UTF-8 characters in the path names. */
        let dirname = String::from(&d.1.clone());
        let mut top_len = topdir_hash[&category_id] as usize;
        /* One more to remove the leading slash of the subpath */
        top_len += 1;
        let subpath: String;
        if top_len > dirname.len() {
            subpath = String::new();
        } else {
            subpath = String::from_utf8_lossy(&dirname.as_bytes()[top_len..]).to_string();
        }
        ml.set_Subpath(subpath);
        let mut global: Vec<i64> = Vec::new();
        let mut by_country: RepeatedField<StringRepeatedIntMap> = RepeatedField::new();
        let mut by_internet2: RepeatedField<StringRepeatedIntMap> = RepeatedField::new();
        let mut by_hostid: RepeatedField<IntRepeatedIntMap> = RepeatedField::new();
        for (h_id, hc_id) in &host_cat_hash[&category_id] {
            let always_up2date: bool = host_cat_id_hash[&(*h_id as i32)];
            let host = get_host(*h_id as i32, hosts);
            if !(always_up2date || hcdir_hc_id_hash.contains_key(&d.0)) {
                continue;
            }
            let mut up2date = false;
            if !always_up2date {
                for hcdir in &hcdir_hc_id_hash[&d.0] {
                    if *hcdir as i64 == *hc_id {
                        up2date = true;
                        break;
                    }
                }
            }

            if !(always_up2date || up2date) {
                continue;
            }

            if !is_host_active(host.clone()) {
                continue;
            }

            // All possible mirrors are part of by_hostid
            if hcurl_cat_url_id_hash.contains_key(hc_id) {
                let hcurl_ids = &hcurl_cat_url_id_hash[hc_id];
                let mut hcurl_id = IntRepeatedIntMap::new();
                hcurl_id.set_key(*h_id);
                hcurl_id.set_value(hcurl_ids.to_vec());
                by_hostid.push(hcurl_id);
            }

            // Private mirrors can still select to be available via Internet2
            if is_host_private(host.clone()) && !host.13 {
                continue;
            }

            if !host.5.is_none() && host.12 {
                let country: String = host.clone().5.unwrap().to_string().to_uppercase();
                let i = find_in_string_repeated_int_map(&by_internet2, &country);
                if i != -1 {
                    let val = &mut by_internet2[i as usize].mut_value();
                    val.push(*h_id);
                } else {
                    let mut bi = StringRepeatedIntMap::new();
                    bi.set_key(country);
                    let val = bi.mut_value();
                    val.push(*h_id);
                    by_internet2.push(bi);
                }
            }

            // But a private mirror should never be added to 'Global'
            if is_host_private(host.clone()) {
                continue;
            }

            global.push(*h_id);

            if host.5.is_none() {
                continue;
            }

            let country: String = host.clone().5.unwrap().to_string().to_uppercase();
            let i = find_in_string_repeated_int_map(&by_country, &country);
            if i != -1 {
                let val = &mut by_country[i as usize].mut_value();
                val.push(*h_id);
            } else {
                let mut bc = StringRepeatedIntMap::new();
                bc.set_key(country);
                let val = bc.mut_value();
                val.push(*h_id);
                by_country.push(bc);
            }
        }
        ml.set_Global(global);
        ml.set_ByCountry(by_country);
        ml.set_ByCountryInternet2(by_internet2);
        ml.set_ByHostId(by_hostid);

        /* Not setting OrderedMirrorList as the rust mirrorlist-server does not read it. */

        mlc.push(ml);
    }
    pb.finish_with_message("done");
    (mlc, fdcdc)
}

/* RepositoryRedirectCache */
fn get_rrc(c: &PgConnection) -> RepeatedField<StringStringMap> {
    let mut rrc: RepeatedField<StringStringMap> = RepeatedField::new();

    let rrc_raw = get_repository_redirects(c);

    for rr in rrc_raw {
        let mut r = StringStringMap::new();
        if !rr.1.is_none() {
            r.set_key(rr.0.clone());
            r.set_value(rr.1.unwrap().clone());
            rrc.push(r);
        }
    }

    rrc
}

/* NetblockCountryCache */
fn get_ncc(c: &PgConnection) -> RepeatedField<StringStringMap> {
    let mut ncc: RepeatedField<StringStringMap> = RepeatedField::new();

    let ncc_raw = get_netblock_countries(c);

    for nc in ncc_raw {
        let mut e = StringStringMap::new();
        e.set_key(nc.0.clone());
        e.set_value(nc.1.clone());
        ncc.push(e);
    }

    ncc
}

/* CountryContinentRedirectCache */
fn get_ccrc(c: &PgConnection) -> RepeatedField<StringStringMap> {
    let mut ccrc: RepeatedField<StringStringMap> = RepeatedField::new();

    let ccrc_raw = get_country_continent_redirects(c);

    for ccr in ccrc_raw {
        let mut cc = StringStringMap::new();
        cc.set_key(ccr.0.clone());
        cc.set_value(ccr.1.clone());
        ccrc.push(cc);
    }

    ccrc
}

/* DisabledRepositoryCache */
fn get_drc(repositories: &Vec<Repository>) -> RepeatedField<StringBoolMap> {
    let mut drc: RepeatedField<StringBoolMap> = RepeatedField::new();

    for r in repositories {
        let mut dr = StringBoolMap::new();
        if !r.0.is_none() && r.5 {
            dr.set_key(r.0.as_ref().unwrap().clone());
            dr.set_value(r.5);
            drc.push(dr);
        }
    }

    drc
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let mut config_file = String::from("/etc/mirrormanager/generate-mirrorlist-cache.cfg");
    let mut cache_file = String::from("/var/lib/mirrormanager/mirrorlist_cache.proto");
    let args: Vec<String> = env::args().map(|x| x.to_string()).collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optmulti(
        "o",
        "outfile",
        &format!("protobuf cache file location ({})", cache_file),
        "CACHE",
    );

    opts.optmulti(
        "c",
        "config",
        &format!("configuration file ({})", config_file),
        "CONFIG",
    );

    opts.optflagmulti("d", "debug", "enable debug");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        _ => {
            print_usage(&program, opts);
            return;
        }
    };

    if matches.opt_present("outfile") {
        cache_file = matches.opt_strs("outfile")[matches.opt_count("outfile") - 1].to_string();
    }

    if matches.opt_present("config") {
        config_file = matches.opt_strs("config")[matches.opt_count("config") - 1].to_string();
    }

    if matches.opt_present("debug") {
        DEBUG.fetch_add(1, Ordering::SeqCst);
    }

    let connection = pg_conn(config_file);
    let mut mirrorlist = MirrorList::new();

    {
        let now: DateTime<Utc> = Utc::now();
        mirrorlist.set_Time(now.timestamp() as u64);
    }

    let hosts = get_hosts(&connection);
    let directories = get_directories(&connection);
    let host_category_urls = get_host_category_urls(&connection);

    {
        /* HostCountryAllowedCache */
        let hcac = get_hcac(&connection, &hosts);
        mirrorlist.set_HostCountryAllowedCache(hcac);
    }

    {
        /* HCUrlCache */
        let hcurls = get_hcurlc(&host_category_urls);
        mirrorlist.set_HCUrlCache(hcurls);
    }

    {
        /* HostNetBlockCache */
        let hnbc = get_hnbc(&connection, &hosts);
        mirrorlist.set_HostNetblockCache(hnbc);
    }

    {
        /* HostBandwidthCache */
        let hbc = get_hbc(&hosts);
        mirrorlist.set_HostBandwidthCache(hbc);
    }

    {
        /* HostCountryCache */
        let hcc = get_hcc(&hosts);
        mirrorlist.set_HostCountryCache(hcc);
    }

    {
        /* HostAsnCache */
        let hac = get_hac(&hosts);
        mirrorlist.set_HostAsnCache(hac);
    }

    {
        /* HostMaxConnectionCache - Not actually used. */
        let hmcc = get_hmcc(&hosts);
        mirrorlist.set_HostMaxConnectionCache(hmcc);
    }

    {
        /* MirrorListCache */
        let (mlc, fdc) = get_mlc(&connection, &hosts, &directories, &host_category_urls);
        mirrorlist.set_MirrorListCache(mlc);
        mirrorlist.set_FileDetailsCache(fdc);
    }

    {
        let repositories = get_repositories(&connection);
        /* RepoArchToDirectoryName */
        let ratdn = get_ratdn(&connection, &directories, &repositories);
        mirrorlist.set_RepoArchToDirectoryName(ratdn);
        /* DisabledRepositoryCache */
        let drc = get_drc(&repositories);
        mirrorlist.set_DisabledRepositoryCache(drc);
    }

    {
        /* RepositoryRedirectCache */
        let rrc = get_rrc(&connection);
        mirrorlist.set_RepositoryRedirectCache(rrc);
    }

    {
        /* CountryContinentRedirectCache */
        let ccrc = get_ccrc(&connection);
        mirrorlist.set_CountryContinentRedirectCache(ccrc);
    }

    {
        /* NetblockCountryCache */
        let ncc = get_ncc(&connection);
        mirrorlist.set_NetblockCountryCache(ncc);
    }

    print_step(format!("Writing to {}", &cache_file));
    let mut file = match File::create(&cache_file).map_err(ProtobufError::IoError) {
        Ok(file) => file,
        _ => {
            println!("Error opening file {}", &cache_file);
            process::exit(1);
        }
    };
    let mut cos = CodedOutputStream::new(&mut file);
    let ret = mirrorlist.write_to(&mut cos);
    if ret.is_err() {
        println!(
            "Error writing to file {} : {:#?}",
            cache_file,
            ret.expect("Error: ")
        );
        process::exit(1);
    }
    cos.flush().unwrap();
}

#[cfg(test)]
mod generate_mirrorlist_cache_test;
