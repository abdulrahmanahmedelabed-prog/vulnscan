<?php
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
$ctx = stream_context_create(['ssl' => ['verify_peer' => true]]);
$client = new GuzzleHttp\Client(['verify' => '/etc/ssl/certs/corp-ca.pem']);
$cipher = openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);
header("Access-Control-Allow-Origin: https://app.corp.internal");
