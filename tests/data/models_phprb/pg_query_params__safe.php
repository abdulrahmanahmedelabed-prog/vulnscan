<?php // expect-none: DF004
function handler($request)
{
    $r = pg_query_params($conn, 'SELECT * FROM t WHERE a = $1', array($_GET['a']));
}
