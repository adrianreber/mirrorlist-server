table! {
    host (id) {
        id -> Integer,
        name -> Text,
        site_id -> Integer,
        admin_active -> Bool,
        user_active -> Bool,
        bandwidth_int -> Integer,
        country -> Nullable<Text>,
        asn_clients -> Bool,
        asn -> Nullable<Integer>,
        max_connections -> Integer,
        private -> Bool,
        internet2 -> Bool,
        internet2_clients -> Bool,
    }
}
table! {
    site (id) {
        id -> Integer,
        user_active -> Bool,
        admin_active -> Bool,
        private -> Bool,
    }
}

table! {
    host_netblock (id) {
        id -> Integer,
        host_id -> Integer,
        netblock -> Text,
    }
}

table! {
    host_country_allowed (id) {
        id -> Integer,
        host_id -> Integer,
        country -> Text,
    }
}

table! {
    host_category (id) {
        id -> Integer,
        host_id -> Nullable<Integer>,
        category_id -> Nullable<Integer>,
        always_up2date -> Bool,
    }
}

table! {
    directory (id) {
        id -> Integer,
        name -> Text,
    }
}

table! {
    category_directory (category_id) {
        category_id -> Integer,
        directory_id -> Integer,
    }
}

table! {
    host_category_url (id) {
        id -> Integer,
        host_category_id -> Integer,
        url -> Text,
        private -> Bool,
    }
}

table! {
    host_category_dir (id) {
        id -> Integer,
        host_category_id -> Integer,
        path -> Nullable<Text>,
        up2date -> Bool,
        directory_id -> Integer,
    }
}

table! {
    category (id) {
        id -> Integer,
        topdir_id -> Integer,
    }
}

table! {
    repository (id) {
        id -> Integer,
        prefix -> Nullable<Text>,
        category_id -> Nullable<Integer>,
        version_id -> Nullable<Integer>,
        arch_id -> Nullable<Integer>,
        directory_id -> Nullable<Integer>,
        disabled -> Bool,
    }
}

table! {
    arch (id) {
        id -> Integer,
        name -> Text,
    }
}

table! {
    repository_redirect (id) {
        id -> Integer,
        from_repo -> Text,
        to_repo -> Nullable<Text>,
    }
}

table! {
    country_continent_redirect (id) {
        id -> Integer,
        country -> Text,
        continent -> Text,
    }
}

table! {
    netblock_country (id) {
        id -> Integer,
        netblock -> Text,
        country -> Text,
    }
}

table! {
    file_detail (id) {
        id -> Integer,
        directory_id -> Integer,
        filename -> Text,
        timestamp -> Nullable<BigInt>,
        size -> Nullable<BigInt>,
        sha1 -> Nullable<Text>,
        md5 -> Nullable<Text>,
        sha256 -> Nullable<Text>,
        sha512 -> Nullable<Text>,
    }
}

joinable!(host -> site (site_id));

allow_tables_to_appear_in_same_query!(site, host);
