// expect: DF004
use actix_web::{get, web, HttpResponse};
use sqlx::MySqlPool;

#[get("/orders/{id}")]
async fn order(pool: web::Data<MySqlPool>, path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let sql = format!("SELECT * FROM orders WHERE id = {}", id);
    let row = sqlx::query_as::<_, Order>(&sql).fetch_one(pool.get_ref()).await.unwrap();
    HttpResponse::Ok().json(row.total)
}
