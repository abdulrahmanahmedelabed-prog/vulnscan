<?php
define('PAGE_ROOT', '../');
$level = 'impossible.php';
switch ($_COOKIE['security']) {
    case 'low':
        $level = 'low.php';
        break;
    default:
        $level = 'impossible.php';
}
require_once PAGE_ROOT . "fi/source/{$level}";
if (isset($file))
    include($file);
