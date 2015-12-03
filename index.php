<?php
require 'ssl.php';

/*
creates keys in folder
@parm optional integer - provide how many bits should be used to generate a private key default 2048
@parm optional string - provide folder to place key files default folder containing this file
*/
ssl::create(2048);

/* load a giant piece of text into a string */
$data = file_get_contents('copy.txt');

echo '<p>Data Length: '.strlen($data).'</p>';

/*
encrypt the data and place in foo
@parm required string - data to encrypt 
@parm optional string - path to key file default filenamed public.key in the folder containing this file
*/
$foo = ssl::encrypt($data);

echo '<p>Foo Length: '.strlen($foo).'</p>';

/* data and foo should not match */
echo ($foo !== $data) ? '<p>Passed</p>' : '<p>Failed</p>';

/*
decrypt foo and place back in foo
@parm required string - data to decrypt
@parm optional string - path to key file default filenamed private.key in the folder containing this file
*/
$foo = ssl::decrypt($foo);

echo '<p>Foo Length: '.strlen($foo).'</p>';

/* data and foo should now match */
echo ($data === $foo) ? '<p>Passed</p>' : '<p>Failed</p>';

echo '<p>Data Length: '.strlen($data).'</p>';
