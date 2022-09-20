use crate::db::schema::{host, site};

#[derive(Queryable, Identifiable, Associations)]
#[diesel(belongs_to(Site))]
#[diesel(table_name = host)]
pub struct Host {
    pub id: i32,
    pub name: String,
    pub site_id: i32,
    pub user_active: bool,
    pub admin_active: bool,
    pub bandwidth_int: i32,
    pub country: String,
    pub asn_clients: bool,
    pub asn: i32,
    pub max_connections: i32,
    pub private: bool,
    pub internet2: bool,
    pub internet2_clients: bool,
}
#[derive(Queryable, Identifiable)]
#[diesel(table_name = site)]
pub struct Site {
    pub id: i32,
    pub user_active: bool,
    pub admin_active: bool,
    pub private: bool,
}
#[derive(Queryable)]
pub struct HostNetblock {
    pub id: i32,
    pub host_id: i32,
    pub netblock: String,
}
#[derive(Queryable)]
pub struct HostCountryAllowed {
    pub id: i32,
    pub host_id: i32,
    pub country: String,
}

#[derive(Queryable)]
pub struct HostCategory {
    pub id: i32,
    pub host_id: i32,
    pub category_id: i32,
    pub always_up2date: bool,
}

#[derive(Queryable)]
pub struct Directory {
    pub id: i32,
    pub name: String,
}

#[derive(Queryable)]
pub struct CategoryDirectory {
    pub category_id: i32,
    pub directory_id: i32,
}

#[derive(Queryable)]
pub struct HostCategoryDirectory {
    pub id: i32,
    pub host_category_id: i32,
    pub path: String,
    pub up2date: bool,
    pub directory_id: i32,
}

#[derive(Queryable)]
pub struct HostCategoryUrl {
    pub id: i32,
    pub host_category_id: i32,
    pub url: String,
    pub private: bool,
}

#[derive(Queryable)]
pub struct Category {
    pub id: i32,
    pub topdir_id: i32,
}

#[derive(Queryable)]
pub struct Repository {
    pub id: i32,
    pub prefix: String,
    pub category_id: i32,
    pub version_id: i32,
    pub arch_id: i32,
    pub directoriy_id: i32,
    pub disabled: bool,
}

#[derive(Queryable)]
pub struct Arch {
    pub id: i32,
    pub name: String,
}

#[derive(Queryable)]
pub struct RepositoryRedirect {
    pub id: i32,
    pub from_repo: String,
    pub to_repo: String,
}

#[derive(Queryable)]
pub struct CountryContinentRedirect {
    pub id: i32,
    pub country: String,
    pub continent: String,
}

#[derive(Queryable)]
pub struct NetblockCountry {
    pub id: i32,
    pub netblock: String,
    pub country: String,
}

#[derive(Queryable)]
pub struct FileDetail {
    pub id: i32,
    pub directory_id: i32,
    pub filename: String,
    pub timestamp: i64,
    pub size: i64,
    pub sha1: String,
    pub md5: String,
    pub sha256: String,
    pub sha512: String,
}
