<?php
$file = $_GET['page'];
if (!in_array($file, array('include.php', 'file1.php'))) {
    echo "ERROR: File not found!";
    exit;
}
