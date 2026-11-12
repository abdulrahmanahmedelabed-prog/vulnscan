// expect-none: DF004
use actix_web::{get, web, HttpResponse};
use sqlx::PgPool;

#[get("/users")]
async fn users(pool: web::Data<PgPool>, info: web::Query<Filter>) -> HttpResponse {
    let rows = sqlx::query("SELECT id, email FROM users WHERE name = $1")
        .bind(&info.name)
        .fetch_all(pool.get_ref())
        .await
        .unwrap();
    HttpResponse::Ok().json(rows.len())
}
