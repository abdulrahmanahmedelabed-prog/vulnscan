// expect-none: DF010
use actix_web::{get, web, HttpResponse};
use hyper::{Body, Client, Request};

#[get("/mirror")]
async fn mirror(info: web::Query<Mirror>) -> HttpResponse {
    let outbound = Request::get("https://mirror.example.com/index").body(Body::empty()).unwrap();
    let resp = Client::new().request(outbound).await.unwrap();
    HttpResponse::Ok().body(resp.status().as_u16().to_string())
}
