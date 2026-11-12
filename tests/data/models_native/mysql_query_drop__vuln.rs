// expect: DF004
use mysql::prelude::*;
use rocket::post;

#[post("/tags/<tag>")]
fn add_tag(tag: String) -> String {
    let mut conn = pool().get_conn().unwrap();
    conn.query_drop(format!("INSERT INTO tags (name) VALUES ('{}')", tag)).unwrap();
    String::from("ok")
}
