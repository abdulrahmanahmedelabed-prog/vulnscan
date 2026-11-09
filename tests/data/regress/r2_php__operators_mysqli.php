<?php
$action = $_GET['action'] ?? '';
if ($action === 'view') {
    readfile("/var/www/files/" . $_GET['file']);
}
if ($action !== '') {
    echo "<p>Action: " . $_GET['action'] . "</p>";
}
$where = "1=1";
foreach ($_GET as $k => $v) {
    $where .= " AND $k = '" . $v . "'";
}
$pdo = new PDO("mysql:host=localhost");
$pdo->query("SELECT * FROM products WHERE " . $where);
$x ??= $_GET['y'];
$id = $_GET['id'];
mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
