// expect: DF005
use std::fs::File;
use std::path::Path;
use tar::Archive;

fn unpack(archive_file: File, dest: &Path) {
    let mut archive = Archive::new(archive_file);
    for item in archive.entries().unwrap() {
        let mut entry = item.unwrap();
        let target = dest.join(entry.path().unwrap());
        let mut out = File::create(&target).unwrap();
        std::io::copy(&mut entry, &mut out).unwrap();
    }
}
