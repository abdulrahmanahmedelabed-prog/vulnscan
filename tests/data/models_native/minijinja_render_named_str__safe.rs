// expect-none: DF007
use minijinja::{context, Environment};
use rocket::post;

#[post("/render/<source>")]
fn render(source: String) -> String {
    let env = Environment::new();
    let out = env.render_named_str("inline", "Hi {{ who }}", context! { who => source }).unwrap();
    out.len().to_string()
}
