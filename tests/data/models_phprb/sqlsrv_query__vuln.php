<?php // expect: DF004
function handler($request)
{
    $r = sqlsrv_query($conn, "SELECT * FROM t WHERE a = '" . $_POST['a'] . "'");
}
