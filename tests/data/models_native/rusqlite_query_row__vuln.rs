// expect: DF004
use rocket::get;
use rusqlite::Connection;

#[get("/count/<table>")]
fn count(table: String) -> String {
    let db = Connection::open("app.db").unwrap();
    let sql = format!("SELECT COUNT(*) FROM {}", table);
    let n: i64 = db.query_row(&sql, [], |r| r.get(0)).unwrap();
    n.to_string()
}
