<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreReportRequest;
use Illuminate\Http\Request;

class ReportController extends Controller
{
    public function show(Request $request, string $name)
    {
        return response()->file(storage_path('reports/' . $name . '.' . $request->query('format')));
    }

    public function store(StoreReportRequest $request)
    {
        return $request->validated();
    }

    public function export(Request $request)
    {
        $out = shell_exec('report-export ' . $request->input('range'));
        return response($out);
    }

    public function webhook(Request $request)
    {
        return unserialize(base64_decode($request->getContent()));
    }
}
