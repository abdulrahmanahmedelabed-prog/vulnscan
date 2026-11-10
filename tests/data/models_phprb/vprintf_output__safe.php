<?php // expect-none: DF013
function handler($request)
{
    vprintf('<p>Hello %s</p>', [htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8')]);
}
