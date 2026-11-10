<?php // expect-none: DF001
function handler($request)
{
    forward_static_call('Report::build', $_GET['fn']);
}
