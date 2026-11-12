// expect: DF010
use rocket::get;

#[get("/avatar/<source>")]
fn avatar(source: String) -> String {
    let fetcher = reqwest::blocking::Client::new();
    let resp = fetcher.get(source).send().unwrap();
    resp.status().as_u16().to_string()
}
