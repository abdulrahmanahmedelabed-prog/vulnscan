<?php // expect: DF004
function handler($request)
{
    $r = pg_query_params($conn, "SELECT * FROM t WHERE a = '" . $_GET['a'] . "'", array());
}
