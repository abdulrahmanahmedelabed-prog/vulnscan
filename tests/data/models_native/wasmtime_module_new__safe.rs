// expect-none: DF012
use actix_web::{post, web, HttpResponse};
use wasmtime::{Engine, Module};

#[post("/plugins")]
async fn plugin(body: web::Bytes) -> HttpResponse {
    let engine = Engine::default();
    let module = Module::new(&engine, BUILTIN_PLUGIN).unwrap();
    HttpResponse::Ok().body(module.exports().count().to_string())
}
