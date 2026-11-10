<?php // expect: DF013
function handler($request)
{
    $body = $request->getParsedBody();
    $response->getBody()->write('Hello ' . $body['name']);
}
