// expect-none: DF004
use diesel::prelude::*;
use diesel::sql_types::Text;
use rocket::get;

#[get("/audit/<actor>")]
fn audit(actor: String) -> String {
    let mut conn = establish();
    let rows: Vec<Audit> = diesel::sql_query("SELECT * FROM audit WHERE actor = $1")
        .bind::<Text, _>(actor)
        .load(&mut conn)
        .unwrap();
    rows.len().to_string()
}
