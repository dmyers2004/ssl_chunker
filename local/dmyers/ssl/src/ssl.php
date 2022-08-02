<?php

declare(strict_types=1);

namespace dmyers\ssl;

/**
 *
 * This content is released under the MIT License (MIT)
 *
 * @author	Don Myers
 * @license	http://opensource.org/licenses/MIT	MIT License
 * @link	https://github.com/ProjectOrangeBox
 */

class ssl
{
	/**
	 * Method create
	 * 
	 * Create Private and Public Keys
	 *
	 * @param $bits $bits [explicite description]
	 * @param $folder $folder [explicite description]
	 *
	 * @return void
	 */
	public function create(int $bits = 2048, string $folder): void
	{
		$folder = ($folder) ? rtrim($folder, '/') : __DIR__;

		$publicFile = $folder . '/public.key';
		$privateFile = $folder . '/private.key';

		if (file_exists($publicFile)) {
			throw new sslException('public key file already exists');
		}

		if (file_exists($privateFile)) {
			throw new sslException('private key file already exists');
		}

		if (!is_writable($folder)) {
			throw new sslException('folder is not writable');
		}

		/* make keys */

		$privateKey = openssl_pkey_new([
			'private_key_bits' => $bits,
			'private_key_type' => OPENSSL_KEYTYPE_RSA,
		]);

		openssl_pkey_export_to_file($privateKey, $privateFile);

		$publicKey = openssl_pkey_get_details($privateKey);

		file_put_contents($publicFile, $publicKey['key']);
	}

	/**
	 * Method encrypt
	 *
	 * @param $data $data [explicite description]
	 * @param $keyFile $keyFile [explicite description]
	 *
	 * @return void
	 */
	public function encrypt(string $data, string $keyFile): string
	{
		if (!file_exists($keyFile)) {
			throw new sslException('Count not locate public key file');
		}

		$key = openssl_pkey_get_public('file://' . $keyFile);

		if (!$key) {
			throw new sslException('Could not open public key');
		}

		$details = openssl_pkey_get_details($key);

		$length = (int)ceil($details['bits'] / 8) - 11;

		$output = '';

		while ($data) {
			$chunk = substr($data, 0, $length);
			$data = substr($data, $length);
			$encrypted = '';

			if (!openssl_public_encrypt($chunk, $encrypted, $key)) {
				throw new sslException('Failed to encrypt data');
			}

			$output .= $encrypted;
		}

		return $output;
	}

	/**
	 * Method decrypt
	 *
	 * @param $data $data [explicite description]
	 * @param $keyFile $keyFile [explicite description]
	 *
	 * @return void
	 */
	public function decrypt(string $data, string $keyFile): string
	{
		if (!file_exists($keyFile)) {
			throw new sslException('Count not locate private key');
		}

		$key = openssl_pkey_get_private('file://' . $keyFile);

		if (!$key) {
			throw new sslException('Could not open private key');
		}

		$details = openssl_pkey_get_details($key);

		$length = (int)ceil($details['bits'] / 8);

		$output = '';

		while ($data) {
			$chunk = substr($data, 0, $length);
			$data = substr($data, $length);
			$decrypted = '';

			if (!openssl_private_decrypt($chunk, $decrypted, $key)) {
				throw new sslException('Failed to decrypt data');
			}

			$output .= $decrypted;
		}

		return $output;
	}
} /* end class */
