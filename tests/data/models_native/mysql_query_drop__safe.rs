// expect-none: DF004
use mysql::prelude::*;
use rocket::post;

#[post("/tags/<tag>")]
fn add_tag(tag: String) -> String {
    let mut conn = pool().get_conn().unwrap();
    conn.exec_drop("INSERT INTO tags (name) VALUES (?)", vec![mysql::Value::from(tag)]).unwrap();
    String::from("ok")
}
