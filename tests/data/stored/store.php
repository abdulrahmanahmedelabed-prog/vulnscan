<?php
$pdo = new PDO($dsn);
$stmt = $pdo->prepare("INSERT INTO posts (content) VALUES (:content)");
$stmt->execute([':content' => $_POST['content']]);
$rows = $pdo->query("SELECT content FROM posts")->fetchAll();
foreach ($rows as $r) {
    echo $r['content'];
}
