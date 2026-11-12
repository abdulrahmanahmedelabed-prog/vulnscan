// expect-none: DF010
use rocket::get;

#[get("/cache/<node>")]
fn cache(node: String) -> String {
    let client = redis::Client::open("redis://cache.internal/").unwrap();
    client.get_connection().is_ok().to_string()
}
