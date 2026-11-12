// expect: DF006
use actix_web::{post, web, HttpResponse};

#[post("/session/restore")]
async fn restore(body: web::Bytes) -> HttpResponse {
    let (state, _len): (SessionState, usize) =
        bincode::decode_from_slice(&body, bincode::config::standard()).unwrap();
    HttpResponse::Ok().body(state.steps.len().to_string())
}
