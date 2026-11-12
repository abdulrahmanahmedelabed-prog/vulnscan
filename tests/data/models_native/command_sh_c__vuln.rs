// expect: DF002
use rocket::get;
use std::process::Command;

#[get("/ping/<host>")]
fn ping(host: String) -> String {
    let line = format!("ping -c 1 {}", host);
    let out = Command::new("sh").arg("-c").arg(&line).output().unwrap();
    String::from_utf8_lossy(&out.stdout).len().to_string()
}
