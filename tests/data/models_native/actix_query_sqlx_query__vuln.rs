// expect: DF004
use actix_web::{get, web, HttpResponse};
use sqlx::PgPool;

#[get("/users")]
async fn users(pool: web::Data<PgPool>, info: web::Query<Filter>) -> HttpResponse {
    let sql = format!("SELECT id, email FROM users WHERE name = '{}'", info.name);
    let rows = sqlx::query(&sql).fetch_all(pool.get_ref()).await.unwrap();
    HttpResponse::Ok().json(rows.len())
}
