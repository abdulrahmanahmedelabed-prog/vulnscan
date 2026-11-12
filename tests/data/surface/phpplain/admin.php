<?php
session_start();
require_once 'includes/db.php';
if (!isset($_SESSION['user_id'])) {
    header('Location: /login.php');
    exit;
}
$id = $_POST['id'];
run_query("DELETE FROM accounts WHERE id = " . $id);
