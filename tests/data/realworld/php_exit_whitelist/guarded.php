<?php
$page = $_GET['page'];
if (!in_array($page, array('home.php', 'about.php'))) {
    echo "not allowed";
    exit;
}
include($page);
$name = $_GET['name'];
if (!preg_match('/^[a-z]+$/', $name)) die("bad name");
echo $name;
