// expect: DF004
use diesel::prelude::*;
use rocket::get;

#[get("/audit/<actor>")]
fn audit(actor: String) -> String {
    let mut conn = establish();
    let stmt = format!("SELECT * FROM audit WHERE actor = '{}'", actor);
    let rows: Vec<Audit> = diesel::sql_query(stmt).load(&mut conn).unwrap();
    rows.len().to_string()
}
