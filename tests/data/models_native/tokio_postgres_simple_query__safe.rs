// expect-none: DF004
use actix_web::{post, web, HttpResponse};

#[post("/maintenance")]
async fn maintenance(pg: web::Data<tokio_postgres::Client>, form: web::Form<Job>) -> HttpResponse {
    pg.simple_query("VACUUM ANALYZE").await.unwrap();
    HttpResponse::Ok().finish()
}
