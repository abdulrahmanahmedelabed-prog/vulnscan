// expect-none: DF005 DF011
use std::fs::File;
use std::path::Path;

fn extract(reader: File, dest: &Path) {
    let mut archive = zip::ZipArchive::new(reader).unwrap();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).unwrap();
        if let Some(rel) = file.enclosed_name() {
            let out_path = dest.join(rel);
            let mut out = File::create(&out_path).unwrap();
            std::io::copy(&mut file, &mut out).unwrap();
        }
    }
}
