// expect: DF005
use actix_files::NamedFile;
use actix_web::{get, HttpRequest};

#[get("/static/{tail:.*}")]
async fn asset(req: HttpRequest) -> actix_web::Result<NamedFile> {
    let tail = req.match_info().query("tail");
    let file = NamedFile::open_async(format!("./public/{}", tail)).await?;
    Ok(file)
}
