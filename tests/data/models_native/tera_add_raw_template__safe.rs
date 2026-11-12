// expect-none: DF007
use actix_web::{post, web, HttpResponse};
use tera::{Context, Tera};

#[post("/preview")]
async fn preview(form: web::Form<Preview>) -> HttpResponse {
    let mut tera = Tera::default();
    tera.add_raw_template("preview", "<p>{{ body }}</p>").unwrap();
    let mut ctx = Context::new();
    ctx.insert("body", &form.body);
    let html = tera.render("preview", &ctx).unwrap();
    HttpResponse::Ok().content_type("text/plain").body(html.len().to_string())
}
