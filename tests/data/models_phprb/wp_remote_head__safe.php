<?php // expect-none: DF010
function handler($request)
{
    $r = wp_remote_head('https://api.wordpress.org/core/version-check/1.7/');
}
