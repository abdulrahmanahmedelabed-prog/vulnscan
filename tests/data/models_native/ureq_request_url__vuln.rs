// expect: DF010
use rocket::post;

#[post("/notify/<endpoint>")]
fn notify(endpoint: String) -> String {
    ureq::request("POST", &endpoint).send_string("ping").unwrap();
    String::from("sent")
}
