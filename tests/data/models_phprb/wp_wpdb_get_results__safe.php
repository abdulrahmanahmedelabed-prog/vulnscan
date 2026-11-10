<?php // expect-none: DF004
function handler($request)
{
    global $wpdb;
    return $wpdb->get_results($wpdb->prepare("SELECT * FROM wp_posts WHERE post_title = %s", $_POST['title']));
}
