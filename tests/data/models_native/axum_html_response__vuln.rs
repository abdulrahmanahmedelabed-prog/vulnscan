// expect: DF013
use axum::extract::Query;
use axum::response::Html;

async fn greet(query: Query<Greeting>) -> Html<String> {
    let who = query.who.clone();
    Html(format!("<h1>Hello {}</h1>", who))
}
