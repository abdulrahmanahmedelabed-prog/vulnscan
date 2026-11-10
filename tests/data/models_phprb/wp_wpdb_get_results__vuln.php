<?php // expect: DF004
function handler($request)
{
    global $wpdb;
    return $wpdb->get_results("SELECT * FROM wp_posts WHERE post_title = '" . $_POST['title'] . "'");
}
