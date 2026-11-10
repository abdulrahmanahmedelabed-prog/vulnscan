<?php // expect: DF004
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $name = $request->query->get('name');
        return $this->connection->fetchAllAssociative("SELECT * FROM users WHERE name = '" . $name . "'");
    }
}
