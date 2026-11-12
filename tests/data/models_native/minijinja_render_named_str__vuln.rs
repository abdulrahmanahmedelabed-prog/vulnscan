// expect: DF007
use minijinja::{context, Environment};
use rocket::post;

#[post("/render/<source>")]
fn render(source: String) -> String {
    let env = Environment::new();
    let out = env.render_named_str("inline", &source, context! {}).unwrap();
    out.len().to_string()
}
