use crate::common::protos::mirrormanager::{
    FileDetailsCacheDirectoryType, FileDetailsCacheFilesType, IntIntMap, IntRepeatedIntMap,
    IntRepeatedStringMap, IntStringMap, MirrorListCacheType, StringBoolMap, StringRepeatedIntMap,
    StringStringMap,
};

pub fn find_in_file_details_cache_directory_cache(
    fdcdc: &[FileDetailsCacheDirectoryType],
    dir: &str,
) -> i64 {
    for (index, e) in fdcdc.iter().enumerate() {
        if e.get_directory() == dir {
            return index as i64;
        }
    }
    -1
}

pub fn find_in_mirrorlist_cache(mlc: &[MirrorListCacheType], dir: &str) -> i64 {
    for (index, mirrorlist_cache) in mlc.iter().enumerate() {
        if mirrorlist_cache.get_directory() == dir {
            return index as i64;
        }
    }
    -1
}

pub fn find_in_string_string_map(ssm: &[StringStringMap], key: &str) -> String {
    let mut result = String::new();
    for param in ssm {
        if param.get_key() == key {
            result.push_str(param.get_value());
        }
    }
    result
}

pub fn find_in_string_bool_map(sbm: &[StringBoolMap], key: &str) -> bool {
    for param in sbm {
        if param.get_key() == key {
            return param.get_value();
        }
    }
    false
}

pub fn find_in_int_int_map(iim: &[IntIntMap], key: i64) -> i64 {
    for e in iim {
        if e.get_key() == key {
            return e.get_value();
        }
    }
    0
}

pub fn find_in_int_string_map(ism: &[IntStringMap], key: i64) -> String {
    for e in ism {
        if e.get_key() == key {
            return String::from(e.get_value());
        }
    }
    String::new()
}

pub fn find_in_int_repeated_string_map(irsm: &[IntRepeatedStringMap], key: i64) -> i64 {
    for (index, param) in irsm.iter().enumerate() {
        if param.get_key() == key {
            return index as i64;
        }
    }
    -1
}

pub fn find_in_int_repeated_int_map(irim: &[IntRepeatedIntMap], key: i64) -> i64 {
    for (index, param) in irim.iter().enumerate() {
        if param.get_key() == key {
            return index as i64;
        }
    }
    -1
}

pub fn find_in_string_repeated_int_map(irim: &[StringRepeatedIntMap], key: &str) -> i64 {
    for (index, param) in irim.iter().enumerate() {
        if param.get_key() == key {
            return index as i64;
        }
    }
    -1
}

pub fn find_in_file_details_cache_files_cache(
    fdcfc: &[FileDetailsCacheFilesType],
    file: &str,
) -> i64 {
    for (index, e) in fdcfc.iter().enumerate() {
        if e.get_filename() == file {
            return index as i64;
        }
    }
    -1
}
