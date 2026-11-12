// expect: DF004
use actix_web::{post, web, HttpResponse};
use sea_orm::{ConnectionTrait, DatabaseConnection};

#[post("/schema")]
async fn schema(db: web::Data<DatabaseConnection>, form: web::Form<Tenant>) -> HttpResponse {
    let ddl = format!("CREATE SCHEMA tenant_{}", form.name);
    db.execute_unprepared(&ddl).await.unwrap();
    HttpResponse::Ok().finish()
}
