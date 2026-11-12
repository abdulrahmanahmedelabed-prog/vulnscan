// expect: DF007
use actix_web::{post, web, HttpResponse};
use tera::{Context, Tera};

#[post("/preview")]
async fn preview(form: web::Form<Preview>) -> HttpResponse {
    let mut tera = Tera::default();
    tera.add_raw_template("preview", &form.body).unwrap();
    let html = tera.render("preview", &Context::new()).unwrap();
    HttpResponse::Ok().content_type("text/plain").body(html.len().to_string())
}
