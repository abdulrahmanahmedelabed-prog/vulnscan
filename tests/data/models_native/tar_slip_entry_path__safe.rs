// expect-none: DF005
use std::fs::File;
use std::path::Path;
use tar::Archive;

fn unpack(archive_file: File, dest: &Path) {
    let mut archive = Archive::new(archive_file);
    for item in archive.entries().unwrap() {
        let mut entry = item.unwrap();
        entry.unpack_in(dest).unwrap();
    }
}
