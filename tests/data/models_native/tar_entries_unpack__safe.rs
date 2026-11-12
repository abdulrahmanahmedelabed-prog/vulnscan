// expect-none: DF005 DF011
use std::fs::File;
use std::path::Path;

fn unpack(tarball: File, dest: &Path) {
    let mut archive = tar::Archive::new(tarball);
    for item in archive.entries().unwrap() {
        let mut member = item.unwrap();
        member.unpack_in(dest).unwrap();
    }
}
