// expect: DF015
use actix_web::{get, web, HttpResponse};
use sxd_document::parser;
use sxd_xpath::evaluate_xpath;

#[get("/catalog")]
async fn catalog(info: web::Query<Pick>) -> HttpResponse {
    let package = parser::parse(CATALOG_XML).unwrap();
    let doc = package.as_document();
    let expr = format!("/catalog/book[@id='{}']/title", info.id);
    let value = evaluate_xpath(&doc, &expr).unwrap();
    HttpResponse::Ok().body(value.string().len().to_string())
}
