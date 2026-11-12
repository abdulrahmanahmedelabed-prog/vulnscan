<?php
class UserRepo
{
    private PDO $db;
    protected ?string $table = null;

    public function __construct(PDO $db)
    {
        $this->db = $db;
    }

    public function find(string $id): array
    {
        return $this->db->query("SELECT * FROM users WHERE id = '" . $id . "'")->fetchAll();
    }
}

$repo = new UserRepo(new PDO("sqlite::memory:"));
$repo->find($_GET['id']);
$run = function (string $cmd): void {
    system("ls " . $cmd);
};
$run($_GET['dir']);
