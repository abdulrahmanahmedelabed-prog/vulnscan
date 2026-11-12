// expect-none: DF004
use rusqlite::{params, Connection};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let conn = Connection::open("app.db").unwrap();
    conn.execute("DELETE FROM notes WHERE title = ?1", params![args[1]]).unwrap();
}
