// expect-none: DF004
use rocket::get;
use rusqlite::Connection;

#[get("/count/<table>")]
fn count(table: String) -> String {
    let db = Connection::open("app.db").unwrap();
    let n: i64 = db.query_row("SELECT COUNT(*) FROM notes WHERE owner = ?1", [table], |r| r.get(0)).unwrap();
    n.to_string()
}
