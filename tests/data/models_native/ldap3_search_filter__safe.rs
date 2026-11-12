// expect-none: DF014
use actix_web::{get, web, HttpResponse};
use ldap3::{ldap_escape, LdapConn, Scope};

#[get("/directory")]
async fn directory(info: web::Query<Lookup>) -> HttpResponse {
    let mut ldap = LdapConn::new("ldap://directory.internal:389").unwrap();
    let filter = format!("(&(objectClass=person)(uid={}))", ldap_escape(&info.name));
    let (rs, _res) = ldap.search("ou=people,dc=example,dc=org", Scope::Subtree, &filter, vec!["cn"]).unwrap().success().unwrap();
    HttpResponse::Ok().body(rs.len().to_string())
}
