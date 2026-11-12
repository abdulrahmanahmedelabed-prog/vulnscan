// expect-none: DF005
use rocket::get;

#[get("/docs/<page>")]
fn docs(page: String) -> String {
    let body = fs_err::read_to_string("docs/index.md").unwrap();
    body.len().to_string()
}
