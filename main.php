<?php

require 'vendor/autoload.php';

$keysFolder = __DIR__ . '/keys';

if (!file_exists($keysFolder)) {
	mkdir($keysFolder);
}

$ssl = new \dmyers\ssl\ssl;

/*
creates keys in folder
@parm optional integer - provide how many bits should be used to generate a private key default 2048
@parm optional string - provide folder to place key files default folder containing this file
*/
if (!file_exists($keysFolder . '/private.key')) {
	$ssl->create(2048, $keysFolder);
}

/* load a giant piece of text into a string */
$copy = file_get_contents('test/copy.txt');

echo 'Copy Length: ' . strlen($copy) . chr(10);

/*
encrypt the data and place in foo
@parm required string - data to encrypt 
@parm optional string - path to key file default filenamed public.key in the folder containing this file
*/
$encrypted = $ssl->encrypt($copy, $keysFolder . '/public.key');

echo 'Encrypted Length: ' . strlen($encrypted) . chr(10);

/* data and foo should not match */
echo ($encrypted !== $copy) ? '++ Passed' : '-- Failed';
echo chr(10);

/*
decrypt foo and place back in foo
@parm required string - data to decrypt
@parm optional string - path to key file default filenamed private.key in the folder containing this file
*/
$decrypted = $ssl->decrypt($encrypted, $keysFolder . '/private.key');

echo 'Decrypted Length: ' . strlen($decrypted) . chr(10);

/* data and foo should now match */
echo ($copy === $decrypted) ? '++ Passed' : '-- Failed';
echo chr(10);

echo 'Copy Length: ' . strlen($copy) . chr(10);
