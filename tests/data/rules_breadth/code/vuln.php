<?php
$ch = curl_init($url);
// expect-next: TLS005
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
// expect-next: TLS005
$ctx = stream_context_create(['ssl' => ['verify_peer' => false]]);
// expect-next: TLS005
$client = new GuzzleHttp\Client(['verify' => false]);
// expect-next: CRY009
$cipher = openssl_encrypt($data, 'des-ede3-cbc', $key, 0, $iv);
// expect-next: CORS002
header("Access-Control-Allow-Origin: " . $_SERVER['HTTP_ORIGIN']);
