// expect-none: DF004
use actix_web::{get, web, HttpResponse};
use sqlx::{Postgres, QueryBuilder};

#[get("/search")]
async fn search(pool: web::Data<sqlx::PgPool>, info: web::Query<Search>) -> HttpResponse {
    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("SELECT * FROM items WHERE owner = ");
    qb.push_bind(&info.owner);
    let rows = qb.build().fetch_all(pool.get_ref()).await.unwrap();
    HttpResponse::Ok().json(rows.len())
}
