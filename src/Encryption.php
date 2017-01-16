<?php
namespace Pentagonal\SimpleEncryption;

use Pentagonal\SimpleEncryption\Cryptography\Sha256;

/**
 * Encryption Instance class
 *
 * usage :
 *     (using mCrypt if possible)
 *     Pentagonal\SimpleEncryption\Encryption::encrypt('string to encrypt', 'saltKey');
 *     (using alternative mCrypt)
 *     Pentagonal\SimpleEncryption\Encryption::altEncrypt('string to encrypt', 'saltKey');
 *     (decryption)
 *     Pentagonal\SimpleEncryption\Encryption::decrypt('string to decrypt', 'saltKey');
 *
 * @package Pentagonal\SimpleEncryption\Cryptography
 * @copyright   Copyright (c) 2017 Pentagonal
 * @link        https://github.com/pentagonal
 * @version     1.0.0
 * @author      pentagonal <org@pentagonal.org>
 * @license GPLv3 or later <https://www.gnu.org/licenses/gpl-3.0.txt>
 */
class Encryption
{
    /* --------------------------------------------------------------------------------*
     |                              Encryption mCrypt                                  |
     |---------------------------------------------------------------------------------|
     */

    /**
     * Current version
     */
    const VERSION            = '1.0.0';

    /**
     * String injection on encoded 64 string value
     */
    const OPENSSL_MIDDLE       = '-oCb';
    const STANDARD_MIDDLE      = '-aCb';

    /**
     * Default Chipper
     */
    const DEFAULT_CHIPPER      = 'AES-256-CBC';

    /**
     * Create Pass Key
     *
     * @param string $key
     * @return array
     * @throws \ErrorException
     */
    private static function createPassKey($key)
    {
        /**
         * ------------------------------------
         * Safe Sanitized hash
         * ------------------------------------
         */
        (is_null($key) || $key === false) && $key = '';
        // safe is use array or object as hash
        $serialize_key      = @serialize($key);
        if (!$serialize_key) {
            throw new \ErrorException(
                sprintf(
                    'Could not serialize input key of %s',
                    gettype($serialize_key)
                )
            );
        }

        /**
         * ------------------------------------
         * Set Key
         * ------------------------------------
         */
        $key       = pack('H*', Sha256::hash($serialize_key));

        return [
            $serialize_key,
            Sha256::safeBase64Encode(str_pad($key, 24, "\0", STR_PAD_RIGHT))
        ];
    }

    /**
     * Decrypt With OpenSSL
     *
     * @param string $key
     * @param string $crypt_text
     * @param string $method
     * @return string
     */
    private static function cryptOpenSSl(
        $key,
        $crypt_text,
        $method = self::DEFAULT_CHIPPER
    ) {
        /**
         * ------------------------------------
         * Doing decryption
         * ------------------------------------
         */
        $chipper = openssl_get_cipher_methods();
        if (!is_string($method) || !in_array($method, $chipper)) {
            $method = self::DEFAULT_CHIPPER;
        }
        $iv_len = openssl_cipher_iv_length($method);
        $strong = false;
        $iv = openssl_random_pseudo_bytes($iv_len, $strong);
        return [
            @openssl_encrypt($crypt_text, $method, $key, 0, $iv),
            $method,
            $iv
        ];
    }

    /**
     * Decrypt With OpenSSL
     *
     * @param string $key
     * @param string $crypt_text
     * @param string $method
     * @param string $iv
     * @return string|bool string on success false if failure
     */
    private static function decryptOpenSSl(
        $key,
        $crypt_text,
        $method,
        $iv
    ) {
        /**
         * ------------------------------------
         * Doing decryption
         * ------------------------------------
         */
        $chipper = openssl_get_cipher_methods();
        if (!is_string($method) || !in_array($method, $chipper)) {
            $method = self::DEFAULT_CHIPPER;
        }

        return @openssl_decrypt($crypt_text, $method, $key, 0, $iv);
    }

    /**
     * Encrypt the string
     * with mCrypt, make sure lib mCrypt is active by your php
     *
     * @param  mixed  $value the value of string to encryption
     * @param  mixed  $hash   key password to save
     * @param  string $method
     *
     * @return string
     * @throws \ErrorException
     */
    public static function encrypt(
        $value,
        $hash = false,
        $method = self::DEFAULT_CHIPPER
    ) {
        /**
         * Using Alternative Encryption
         * if mCrypt not loaded
         */
        if (! extension_loaded('openssl')) {
            return static::altEncrypt($value, $hash, $method);
        }

        /**
         * Serialize Element
         */
        $string = @serialize([
            $value
        ]);
        if (!$string) {
            throw new \ErrorException(
                sprintf(
                    'Could not serialize input of %s',
                    gettype($string)
                )
            );
        }

        $passKey   = self::createPassKey($hash);
        $crypt_arr = self::cryptOpenSSl(
            $passKey[1],
            $string,
            $method
        );

        // encode json
        $microtime = microtime(true);
        $iv = Sha256::base64Encode($crypt_arr[2]);
        $json_value = json_encode([
            'micro'  => $microtime,
            'method' => $crypt_arr[1],
            'iv'     => $iv,
            'value'  => $crypt_arr[0],
        ]);

        // save as bse64 encode safe
        $crypt_text = trim(
            Sha256::safeBase64Encode(
                $json_value .
                json_encode([
                    sha1($microtime . $passKey[1] . $iv)
                ])
            )
        );

        /**
         * ------------------------------------
         * Inject Result of with sign
         * ------------------------------------
         */
        $pos = abs(round(strlen($passKey[0]) / 3));
        if (strlen($crypt_text) > $pos) {
            return substr_replace($crypt_text, self::OPENSSL_MIDDLE . $pos, $pos, 0);
        } else {
            return substr_replace($crypt_text, self::OPENSSL_MIDDLE . $pos, 2, 0);
        }
    }

    public static function decrypt($value, $hash = false)
    {
        if (!is_string($value) || strlen(trim($value)) < 4) {
            return null;
        }

        /**
         * Using Alternative Encryption
         * if mCrypt not loaded
         */
        if (! extension_loaded('openssl')) {
            return static::altDecrypt($value, $hash);
        }

        $passKey          = self::createPassKey($hash);
        $pos              = abs(round(strlen($passKey[0]) / 3));
        $the_val_pos      = (strlen($value) > $pos);
        $length_to_check  =  $the_val_pos ? $pos : 2;
        $length           = strlen(self::OPENSSL_MIDDLE . $pos);
        $string_to_check  = substr($value, $length_to_check, $length);

        if ($string_to_check != self::OPENSSL_MIDDLE . $pos) {
            if ($string_to_check != self::STANDARD_MIDDLE . $pos) {
                return null;
            }

            return static::altDecrypt($value, $hash);
        }

        /**
         * Replace Injection 3 characters sign
         */
        $value = $the_val_pos
            ? substr_replace($value, '', $pos, $length)
            : substr_replace($value, '', 2, $length);

        // this is base64 safe encoded?
        if (preg_match('/[^a-z0-9\+\/\=\-\_]/i', $value)) {
            return null;
        }

        $value = Sha256::safeBase64Decode($value);
        $value = explode('[', $value);
        if (count($value) <> 2) {
            return null;
        }

        $json_decode_value = json_decode($value[0], true);

        if (!is_array($json_decode_value)
            || empty($json_decode_value['method'])
            || empty($json_decode_value['value'])
            || empty($json_decode_value['micro'])
            || empty($json_decode_value['iv'])
        ) {
            return null;
        }
        $json_decode_info  = json_decode('['.$value[1], true);
        if (empty($json_decode_info[0])
            || $json_decode_info[0] != sha1(
                $json_decode_value['micro'] . $passKey[1] . $json_decode_value['iv']
            )
        ) {
            return null;
        }

        $method = $json_decode_value['method'];
        $value  = $json_decode_value['value'];
        $iv     = Sha256::base64Decode($json_decode_value['iv']);
        unset($json_decode_info, $json_decode_value);

        if (strlen($value) <= strlen($passKey[1])) {
            return null;
        }
        if (strlen($value) < 3) {
            return null;
        }
        $decrypted_text = self::decryptOpenSSl($passKey[1], $value, $method, $iv);
        if (!$decrypted_text || strlen($decrypted_text) < 2) {
            return null;
        }
        $decrypted_text = @unserialize($decrypted_text);
        if (!is_array($decrypted_text) || !array_key_exists(0, $decrypted_text)) {
            return null;
        }

        return $decrypted_text[0];
    }

    /* --------------------------------------------------------------------------------*
     |                             Alternative Encryption                              |
     |---------------------------------------------------------------------------------|
     */

    private static function cryptStandard(
        $hash,
        $crypt_text,
        $method = self::DEFAULT_CHIPPER
    ) {
        /**
         * ------------------------------------
         * Doing convert string
         * ------------------------------------
         */
        $crypt_text = Sha256::rotate($crypt_text, (strlen($hash) % 13));
        $add = 0;
        $iv = Sha256::safeBase64Decode(sha1($method . @time()));
        $crypt_text = substr_replace($crypt_text, $iv, strlen($hash), 0);
        $div = strlen($crypt_text) / strlen($hash);
        $new_pass = '';
        while ($add <= $div) {
            $new_pass .= $hash;
            $add++;
        }

        $pass_arr = str_split($new_pass);
        $str_arr  = str_split($crypt_text);
        $ascii = '';
        foreach ($str_arr as $key => $asc) {
            $pass_int = ord($pass_arr[$key]);
            $str_int = ord($asc);
            $int_add = $str_int + $pass_int;
            $ascii .= chr(($int_add+strlen($crypt_text)));
        }

        return [
            Sha256::base64Encode($ascii),
            $method, // for what?
            $iv
        ];
    }

    private static function decryptStandard(
        $hash,
        $crypt_text,
        $method,
        $iv
    ) {
        if (substr($iv, 0, strlen($method)) !== $method) {
            return null;
        }

        /**
         * ------------------------------------
         * Doing convert encrypted string
         * ------------------------------------
         */
        /**
         * Doing decode of input encryption
         */
        $crypt_text = Sha256::safeBase64Decode($crypt_text);
        $enc_arr  = str_split($crypt_text);
        $add = 0;
        $div = strlen($crypt_text) / strlen($hash);
        $new_pass = '';
        while ($add <= $div) {
            $new_pass .= $hash;
            $add++;
        }
        $pass_arr = str_split($new_pass);
        $ascii ='';
        foreach ($enc_arr as $key => $asc) {
            $pass_int = ord($pass_arr[$key]);
            $enc_int = ord($asc);
            $str_int = $enc_int - $pass_int;
            $ascii .= chr(($str_int-strlen($crypt_text)));
        }

        /* --------------------------------
         * reversing
         * ------------------------------ */
        // unpack
        $unpack     = unpack('a*', trim($ascii));
        /**
         * if empty return here
         */
        if (empty($unpack)) {
            return null;
        }

        // implode the unpacking array
        $unpack = implode('', (array) $unpack);
        $iv     = substr($iv, strlen($method));
        $sub_iv = substr($unpack, -strlen($iv));
        if ($sub_iv !== $iv) {
            return null;
        }
        $crypt_text = substr_replace($unpack, '', strlen($hash), strlen($iv));
        return Sha256::rotate($crypt_text, -(strlen($hash) % 13));
    }

    /**
     * Alternative encryption using Pure PHP Libraries
     *
     * @param  mixed  $value    string to be encode
     * @param  mixed  $hash     the hash key
     * @param  string $method   method
     * @return string       encryption string output
     * @throws \ErrorException
     */
    public static function altEncrypt(
        $value,
        $hash = false,
        $method = self::DEFAULT_CHIPPER
    ) {
        /**
         * Serialize Element
         */
        $string = @serialize([
            $value
        ]);
        if (!$string) {
            throw new \ErrorException(
                sprintf(
                    'Could not serialize input of %s',
                    gettype($string)
                )
            );
        }
        $passKey   = self::createPassKey($hash);
        $crypt_arr = self::cryptStandard(
            $passKey[1],
            $string,
            $method
        );

        $microtime = microtime(true);
        $iv = Sha256::base64Encode($method . $crypt_arr[2]);
        $json_value = json_encode([
            'micro'  => $microtime,
            'method' => $crypt_arr[1],
            'iv'     => $iv,
            'value'  => $crypt_arr[0],
        ]);

        // save as bse64 encode safe
        $crypt_text = trim(
            Sha256::safeBase64Encode(
                $json_value .
                json_encode([
                    sha1($microtime . $passKey[1] . $iv)
                ])
            )
        );

        /**
         * ------------------------------------
         * Inject Result of with sign
         * ------------------------------------
         */
        $pos = abs(round(strlen($passKey[0]) / 3));
        if (strlen($crypt_text) > $pos) {
            return substr_replace($crypt_text, self::STANDARD_MIDDLE . $pos, $pos, 0);
        } else {
            return substr_replace($crypt_text, self::STANDARD_MIDDLE . $pos, 2, 0);
        }
    }

    /**
     * Alternative decryption
     *
     * @param mixed $value value to encrypt
     * @param bool  $hash  the hash key
     * @return mixed|null
     */
    public static function altDecrypt($value, $hash = false)
    {
        if (!is_string($value) || strlen(trim($value)) < 4) {
            return null;
        }

        $passKey          = self::createPassKey($hash);
        $pos              = abs(round(strlen($passKey[0]) / 3));
        $the_val_pos      = (strlen($value) > $pos);
        $length_to_check  =  $the_val_pos ? $pos : 2;
        $length           = strlen(self::OPENSSL_MIDDLE . $pos);
        $string_to_check  = substr($value, $length_to_check, $length);

        /**
         * Check if use OpenSSSL encryption or invalid value
         */
        if ($string_to_check != self::STANDARD_MIDDLE . $pos) {
            if (!extension_loaded('openssl')
                || $string_to_check != self::OPENSSL_MIDDLE . $pos) {
                return null;
            }
            return static::decrypt($value, $hash);
        }

        /**
         * Replace Injection
         */
        $value = $the_val_pos
            ? substr_replace($value, '', $pos, $length)
            : substr_replace($value, '', 2, $length);

        // this is base64 safe encoded?
        if (preg_match('/[^a-z0-9\+\/\=\-\_]/i', $value)) {
            return null;
        }

        $value = Sha256::safeBase64Decode($value);
        $value = explode('[', $value);
        if (count($value) <> 2) {
            return null;
        }

        $json_decode_value = json_decode($value[0], true);

        if (!is_array($json_decode_value)
            || empty($json_decode_value['method'])
            || empty($json_decode_value['value'])
            || empty($json_decode_value['micro'])
            || empty($json_decode_value['iv'])
        ) {
            return null;
        }
        $json_decode_info  = json_decode('['.$value[1], true);
        if (empty($json_decode_info[0])
            || $json_decode_info[0] != sha1(
                $json_decode_value['micro'] . $passKey[1] . $json_decode_value['iv']
            )
        ) {
            return null;
        }

        $method = $json_decode_value['method'];
        $value  = $json_decode_value['value'];
        $iv     = Sha256::base64Decode($json_decode_value['iv']);
        unset($json_decode_info, $json_decode_value);
        if (strlen($value) <= strlen($passKey[1])) {
            return null;
        }

        if (strlen($value) < 3) {
            return null;
        }

        $decrypted_text = self::decryptStandard($passKey[1], $value, $method, $iv);
        if (!$decrypted_text || strlen($decrypted_text) < 2) {
            return null;
        }

        $decrypted_text = @unserialize($decrypted_text);
        if (!is_array($decrypted_text) || !array_key_exists(0, $decrypted_text)) {
            return null;
        }

        return $decrypted_text[0];
    }
}
