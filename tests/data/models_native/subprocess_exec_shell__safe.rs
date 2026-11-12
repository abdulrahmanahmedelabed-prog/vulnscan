// expect-none: DF002
use rocket::get;
use subprocess::Exec;

#[get("/archive/<name>")]
fn archive(name: String) -> String {
    Exec::shell("tar czf /tmp/data.tgz /srv/data").join().unwrap();
    String::from("queued")
}
