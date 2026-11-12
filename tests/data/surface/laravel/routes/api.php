<?php

use App\Http\Controllers\ReportController;
use Illuminate\Support\Facades\Route;

Route::group(['prefix' => 'v1', 'middleware' => 'auth:sanctum'], function () {
    Route::post('/reports/export', 'ReportController@export');
});

Route::match(['get', 'post'], '/webhook', [ReportController::class, 'webhook']);
