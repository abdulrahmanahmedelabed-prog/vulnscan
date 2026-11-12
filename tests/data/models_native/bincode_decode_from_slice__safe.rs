// expect-none: DF006
use actix_web::{post, web, HttpResponse};

#[post("/session/restore")]
async fn restore(body: web::Bytes) -> HttpResponse {
    let state: SessionState = serde_json::from_slice(&body).unwrap();
    HttpResponse::Ok().body(state.steps.len().to_string())
}
