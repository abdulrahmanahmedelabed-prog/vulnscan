<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class AdminController
{
    #[Route('/admin/import', methods: ['POST'])]
    public function import(Request $request): Response
    {
        return new Response(file_get_contents($request->request->get('source')));
    }
}
