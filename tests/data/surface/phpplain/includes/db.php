<?php
function run_query($sql)
{
    $link = mysqli_connect('localhost', 'app', getenv('DB_PASS'), 'app');
    return mysqli_query($link, $sql);
}
