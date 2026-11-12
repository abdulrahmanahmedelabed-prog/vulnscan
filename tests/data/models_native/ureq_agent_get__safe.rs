// expect-none: DF010
use rocket::get;

#[get("/proxy/<site>")]
fn proxy(site: String) -> String {
    let agent = ureq::AgentBuilder::new().build();
    let body = agent.get("https://feeds.example.com/latest").call().unwrap().into_string().unwrap();
    body.len().to_string()
}
