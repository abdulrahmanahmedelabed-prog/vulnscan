// expect-none: DF005 DF006 DF011
use std::fs::File;
use std::io::Read;

// a library function whose parameter happens to be called `json` is not a request handler
pub fn from_borrowed(json: &str) -> &RawValue {
    unsafe { std::mem::transmute::<&str, &RawValue>(json) }
}

// std::io::copy moves bytes between a reader and a writer; it takes no path
fn save(mut body: impl Read, dest: &mut File) {
    std::io::copy(&mut body, dest).unwrap();
}
