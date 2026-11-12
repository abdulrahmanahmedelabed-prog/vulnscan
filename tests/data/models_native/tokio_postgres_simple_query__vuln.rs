// expect: DF004
use actix_web::{post, web, HttpResponse};

#[post("/maintenance")]
async fn maintenance(pg: web::Data<tokio_postgres::Client>, form: web::Form<Job>) -> HttpResponse {
    let stmt = format!("VACUUM {}", form.name);
    pg.simple_query(&stmt).await.unwrap();
    HttpResponse::Ok().finish()
}
