// expect-none: DF010
use actix_web::{post, web, HttpResponse};
use reqwest::Method;

#[post("/webhook/test")]
async fn test_hook(form: web::Form<Hook>) -> HttpResponse {
    let http_client = reqwest::Client::new();
    let resp = http_client.request(Method::POST, "https://hooks.example.com/ping").send().await.unwrap();
    HttpResponse::Ok().body(resp.status().as_u16().to_string())
}
