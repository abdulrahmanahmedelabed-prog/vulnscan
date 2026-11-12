// expect-none: DF012
use rocket::get;

#[get("/calc/<formula>")]
fn calc(formula: String) -> String {
    let n: i64 = formula.parse().unwrap();
    (n * 2).to_string()
}
