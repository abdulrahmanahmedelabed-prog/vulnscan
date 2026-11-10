<?php // expect-none: DF005
function handler($request)
{
    $gz = gzopen('/srv/archive/' . basename($_GET['f']), 'r');
}
