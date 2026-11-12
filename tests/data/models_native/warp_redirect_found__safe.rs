// expect-none: DF008
use std::collections::HashMap;
use warp::http::Uri;

async fn login_done(query: HashMap<String, String>) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::redirect::found(Uri::from_static("/home")))
}
