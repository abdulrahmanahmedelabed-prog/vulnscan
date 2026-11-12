// expect: DF010
use actix_web::{get, web, HttpResponse};

#[get("/fetch")]
async fn fetch(info: web::Query<Fetch>) -> HttpResponse {
    let http = reqwest::Client::new();
    let resp = http.get(&info.url).send().await.unwrap();
    HttpResponse::Ok().body(resp.status().as_u16().to_string())
}
