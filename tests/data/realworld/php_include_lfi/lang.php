<?php
$lang = $_REQUEST['lang'];
require_once "lang/" . $lang . ".php";
$theme = 'dark';
include "themes/" . $theme . ".php";
