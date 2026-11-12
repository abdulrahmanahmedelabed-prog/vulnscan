// expect: DF008
use rocket::get;
use rocket::response::Redirect;

#[get("/go?<next>")]
fn go(next: String) -> Redirect {
    Redirect::moved(next)
}
