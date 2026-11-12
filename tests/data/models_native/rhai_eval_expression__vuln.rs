// expect: DF012
use rhai::Engine;
use rocket::get;

#[get("/calc/<formula>")]
fn calc(formula: String) -> String {
    let rhai_engine = Engine::new();
    let n: i64 = rhai_engine.eval_expression(&formula).unwrap();
    n.to_string()
}
