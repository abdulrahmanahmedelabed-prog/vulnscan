// expect: DF006
use actix_web::{post, web, HttpResponse};

#[post("/cbor")]
async fn cbor(body: web::Bytes) -> HttpResponse {
    let doc: Envelope = ciborium::de::from_reader(body.as_ref()).unwrap();
    HttpResponse::Ok().body(doc.items.len().to_string())
}
