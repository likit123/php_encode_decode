<?php

  function encode_decode($string, $action = 'encrypt'){
    $encrypt_method = "AES-256-CBC";
    $secret_key = 'AZLoaj6HH7B62Le#oA$'; // user define private key
    $secret_iv = 'lkjfl@#(hi@#ojljal#A74J'; // user define secret key
    $key = hash('sha256', $secret_key);
    $iv = substr(hash('sha256', $secret_iv), 0, 16); // sha256 is hash_hmac_algo
    if ($action == 'encrypt') {
        $output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
        $output = base64_encode($output);
    } else if ($action == 'decrypt') {
        $output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
    }
    return $output;
  }

  $text="Hello สวัสดี";
  $text_encode=encode_decode($text);
  $text_decode=encode_decode($text_encode,"decrypt");

  echo "text ก่อนเข้ารหัส = $text <br>";
  echo "text เข้ารหัส = $text_encode <br>";
  echo "text ถอดรหัสแล้ว = $text_decode <br>";

?>