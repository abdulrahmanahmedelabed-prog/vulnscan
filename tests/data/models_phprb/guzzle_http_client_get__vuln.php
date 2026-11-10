<?php // expect: DF010
function handler($request)
{
    $res = $this->httpClient->get($_GET['url']);
}
