<?php

namespace App\Http\Controllers;

use App\Models\Photo;

class PhotoController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth')->except(['index', 'show']);
    }

    public function index()
    {
        return Photo::all();
    }

    public function show($photo)
    {
        return Photo::find($photo);
    }

    public function destroy($photo)
    {
        Photo::destroy($photo);
    }
}
