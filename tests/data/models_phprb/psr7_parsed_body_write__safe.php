<?php // expect-none: DF013
function handler($request)
{
    $body = $request->getParsedBody();
    $response->getBody()->write('Hello ' . htmlspecialchars($body['name'], ENT_QUOTES, 'UTF-8'));
}
