<?php // expect-none: DF004
function handler($request)
{
    $r = sqlsrv_query($conn, 'SELECT * FROM t WHERE a = ?', array($_POST['a']));
}
