<?php // expect-none: DF004
function handler($request)
{
    global $wpdb;
    $id = $request->get_param('id');
    return $wpdb->get_var("SELECT post_title FROM wp_posts WHERE ID = " . absint($id));
}
