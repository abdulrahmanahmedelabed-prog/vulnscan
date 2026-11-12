// expect-none: DF010
use rocket::post;

#[post("/notify/<endpoint>")]
fn notify(endpoint: String) -> String {
    ureq::request("POST", "https://notify.example.com/v1").send_string("ping").unwrap();
    String::from("sent")
}
