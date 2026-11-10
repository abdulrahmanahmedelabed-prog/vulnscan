<?php // expect: DF010
function handler($request)
{
    $r = wp_remote_head($_GET['url']);
}
