<?php // expect-none: DF010
function handler($request)
{
    $res = $this->httpClient->get('https://api.example.com/v1/status');
}
