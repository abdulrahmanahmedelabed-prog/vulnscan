<?php
$file = $_GET['file'];
$token = $_COOKIE['sid'];
header('Content-Type: application/octet-stream');
readfile('/var/www/files/' . $file);
