// expect: DF005
use std::fs::File;
use std::path::Path;

fn unpack(tarball: File, dest: &Path) {
    let mut archive = tar::Archive::new(tarball);
    for item in archive.entries().unwrap() {
        let mut member = item.unwrap();
        let name = member.path().unwrap().into_owned();
        let mut out = File::create(dest.join(name)).unwrap();
        std::io::copy(&mut member, &mut out).unwrap();
    }
}
