<?php // expect: DF013
function handler($request)
{
    vprintf('<p>Hello %s</p>', [$_GET['name']]);
}
