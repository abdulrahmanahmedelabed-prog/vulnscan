// expect-none: DF006
use actix_web::{post, HttpResponse};

#[post("/import")]
async fn import(body: String) -> HttpResponse {
    let cfg: Settings = serde_yaml::from_str(include_str!("defaults.yaml")).unwrap();
    HttpResponse::Ok().body(cfg.jobs.len().to_string())
}
