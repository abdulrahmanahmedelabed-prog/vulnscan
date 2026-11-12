// expect: DF004
use actix_web::{get, web, HttpResponse};
use sqlx::{Postgres, QueryBuilder};

#[get("/search")]
async fn search(pool: web::Data<sqlx::PgPool>, info: web::Query<Search>) -> HttpResponse {
    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("SELECT * FROM items ORDER BY ");
    qb.push(&info.sort);
    let rows = qb.build().fetch_all(pool.get_ref()).await.unwrap();
    HttpResponse::Ok().json(rows.len())
}
