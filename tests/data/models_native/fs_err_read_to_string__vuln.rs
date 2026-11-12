// expect: DF005
use rocket::get;

#[get("/docs/<page>")]
fn docs(page: String) -> String {
    let body = fs_err::read_to_string(format!("docs/{}.md", page)).unwrap();
    body.len().to_string()
}
