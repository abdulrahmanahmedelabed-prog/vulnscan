// expect-none: DF015
use actix_web::{get, web, HttpResponse};
use sxd_document::parser;
use sxd_xpath::evaluate_xpath;

#[get("/catalog")]
async fn catalog(info: web::Query<Pick>) -> HttpResponse {
    let package = parser::parse(CATALOG_XML).unwrap();
    let doc = package.as_document();
    let value = evaluate_xpath(&doc, "/catalog/book[1]/title").unwrap();
    HttpResponse::Ok().body(value.string().len().to_string())
}
