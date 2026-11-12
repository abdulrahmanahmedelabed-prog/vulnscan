// expect: DF007
use handlebars::Handlebars;
use rocket::post;

#[post("/mail/<layout>")]
fn mail(layout: String) -> String {
    let mut hb = Handlebars::new();
    hb.register_template_string("mail", layout).unwrap();
    hb.render("mail", &serde_json::json!({})).unwrap().len().to_string()
}
