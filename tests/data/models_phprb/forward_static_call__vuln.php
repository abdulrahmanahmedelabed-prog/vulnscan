<?php // expect: DF001
function handler($request)
{
    forward_static_call($_GET['fn'], 1);
}
