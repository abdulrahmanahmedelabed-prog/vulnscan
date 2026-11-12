// expect-none: DF005
use actix_web::{post, web, HttpResponse};
use tokio::io::AsyncWriteExt;

#[post("/upload")]
async fn upload(form: web::Form<Upload>) -> HttpResponse {
    let id: u64 = form.name.parse().unwrap();
    let target = format!("/var/uploads/{}.bin", id);
    let mut out = tokio::fs::File::create(&target).await.unwrap();
    out.flush().await.unwrap();
    HttpResponse::Ok().finish()
}
