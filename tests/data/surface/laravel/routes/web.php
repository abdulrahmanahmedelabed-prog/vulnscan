<?php

use App\Http\Controllers\PhotoController;
use App\Http\Controllers\ReportController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/search', function (Request $request) {
    $term = $request->input('term');
    return DB::select("SELECT * FROM photos WHERE title LIKE '%" . $term . "%'");
});

Route::middleware(['auth', 'verified'])->prefix('admin')->group(function () {
    Route::get('/reports/{name}', [ReportController::class, 'show']);
    Route::post('/reports', [ReportController::class, 'store'])->middleware('can:create,report');
});

Route::resource('photos', PhotoController::class)->only(['index', 'show', 'destroy']);
