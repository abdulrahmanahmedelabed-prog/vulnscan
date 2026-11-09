<?php
$n = $_GET['n'];
$sql = <<<SQL
SELECT * FROM users WHERE name = '$n'
SQL;
mysqli_query($conn, $sql);
?>
<p>Hello <?= $n ?></p>
