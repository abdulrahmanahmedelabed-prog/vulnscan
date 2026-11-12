// expect-none: DF005
use actix_web::{get, web, HttpResponse};
use std::fs::File;
use std::io::Read;

#[get("/download")]
async fn download(info: web::Query<Download>) -> HttpResponse {
    let name = info.file.clone();
    if !SAFE_NAME.is_match(&name) {
        return HttpResponse::BadRequest().finish();
    }
    let mut f = File::open(format!("/srv/files/{}", name)).unwrap();
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    HttpResponse::Ok().content_type("application/octet-stream").finish()
}
