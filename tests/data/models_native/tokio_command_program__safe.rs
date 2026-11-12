// expect-none: DF002
use actix_web::{post, web, HttpResponse};

#[post("/tools/run")]
async fn run_tool(form: web::Form<Tool>) -> HttpResponse {
    let status = tokio::process::Command::new("/usr/bin/uptime").status().await.unwrap();
    HttpResponse::Ok().body(status.success().to_string())
}
