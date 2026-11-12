// expect-none: DF005 DF011
use std::fs;
use walkdir::WalkDir;

// DirEntry::path() of a directory walk is a local listing, not an archive member chosen by an attacker
fn collect(root: &str) -> Vec<String> {
    let mut out = Vec::new();
    for entry in WalkDir::new(root) {
        let entry = entry.unwrap();
        let path = entry.path();
        out.push(fs::read_to_string(path).unwrap());
    }
    for entry in fs::read_dir("cache").unwrap() {
        let entry = entry.unwrap();
        fs::remove_file(entry.path()).unwrap();
    }
    out
}
