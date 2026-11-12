// expect-none: DF007
use handlebars::Handlebars;
use rocket::post;

#[post("/mail/<layout>")]
fn mail(layout: String) -> String {
    let mut hb = Handlebars::new();
    hb.register_template_string("mail", "Hello {{name}}").unwrap();
    let mut data = std::collections::BTreeMap::new();
    data.insert("name", layout);
    hb.render("mail", &data).unwrap().len().to_string()
}
