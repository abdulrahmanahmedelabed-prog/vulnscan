// expect: DF004
use rusqlite::Connection;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let conn = Connection::open("app.db").unwrap();
    conn.execute(&format!("DELETE FROM notes WHERE title = '{}'", args[1]), []).unwrap();
}
