<?php
$page = $_GET['page'];
if (!in_array($page, array('home.php', 'about.php'))) {
    echo "not allowed";
}
include($page);
die("Unknown user: " . $_GET['user']);
