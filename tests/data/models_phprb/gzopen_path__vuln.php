<?php // expect: DF005
function handler($request)
{
    $gz = gzopen('/srv/archive/' . $_GET['f'], 'r');
}
