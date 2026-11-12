<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/articles')]
class ArticleController extends AbstractController
{
    #[Route('/{slug}', name: 'article_show', methods: ['GET'])]
    public function show(string $slug, Request $request): Response
    {
        $tpl = $request->query->get('tpl');
        return new Response($this->container->get('twig')->createTemplate($tpl)->render(['slug' => $slug]));
    }

    #[Route('/{id}/edit', methods: ['POST'])]
    #[IsGranted('ROLE_EDITOR')]
    public function edit(int $id, Request $request): Response
    {
        return new Response($request->request->get('title'));
    }

    /**
     * @Route("/legacy/list", methods={"GET"})
     */
    public function legacyList(): Response
    {
        return new Response('ok');
    }
}
