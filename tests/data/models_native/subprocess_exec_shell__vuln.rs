// expect: DF002
use rocket::get;
use subprocess::Exec;

#[get("/archive/<name>")]
fn archive(name: String) -> String {
    Exec::shell(format!("tar czf /tmp/{}.tgz /srv/data", name)).join().unwrap();
    String::from("queued")
}
