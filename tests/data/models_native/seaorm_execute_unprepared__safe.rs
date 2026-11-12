// expect-none: DF004
use actix_web::{post, web, HttpResponse};
use sea_orm::{ConnectionTrait, DatabaseConnection};

#[post("/schema")]
async fn schema(db: web::Data<DatabaseConnection>, form: web::Form<Tenant>) -> HttpResponse {
    db.execute_unprepared("CREATE SCHEMA IF NOT EXISTS tenants").await.unwrap();
    HttpResponse::Ok().finish()
}
