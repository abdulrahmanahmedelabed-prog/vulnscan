// expect: DF008
use std::collections::HashMap;
use warp::http::Uri;

async fn login_done(query: HashMap<String, String>) -> Result<impl warp::Reply, warp::Rejection> {
    let next = query.get("next").cloned().unwrap_or_default();
    let uri = Uri::try_from(next.as_str()).unwrap();
    Ok(warp::redirect::found(uri))
}
