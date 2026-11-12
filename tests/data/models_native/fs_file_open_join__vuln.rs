// expect: DF005
use actix_web::{get, web, HttpResponse};
use std::fs::File;
use std::io::Read;

#[get("/download")]
async fn download(info: web::Query<Download>) -> HttpResponse {
    let full = format!("/srv/files/{}", info.file);
    let mut f = File::open(&full).unwrap();
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    HttpResponse::Ok().content_type("application/octet-stream").finish()
}
