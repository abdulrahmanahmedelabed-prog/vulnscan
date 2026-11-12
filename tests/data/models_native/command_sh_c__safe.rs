// expect-none: DF002
use rocket::get;
use std::process::Command;

#[get("/ping/<host>")]
fn ping(host: String) -> String {
    let out = Command::new("sh").arg("-c").arg("ping -c 1 127.0.0.1").output().unwrap();
    String::from_utf8_lossy(&out.stdout).len().to_string()
}
