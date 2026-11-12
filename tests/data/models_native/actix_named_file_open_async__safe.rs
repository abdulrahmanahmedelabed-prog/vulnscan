// expect-none: DF005
use actix_files::NamedFile;
use actix_web::{get, HttpRequest};

#[get("/static/{tail:.*}")]
async fn asset(req: HttpRequest) -> actix_web::Result<NamedFile> {
    let file = NamedFile::open_async("./public/index.html").await?;
    Ok(file)
}
