<?php
namespace Pentagonal\SimpleEncryption;

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

    /* --------------------------------------------------------------------------------*
     |                                  ENCODING                                       |
     |---------------------------------------------------------------------------------|
     */

    /**
     * Encode the values using base64_encode and replace some string
     * and could decode @uses safeBase64Decode()
     *
     * @param  string $string
     * @return string
     */
    public static function safeBase64Encode($string)
    {
        $data = base64_encode($string);
        $data = str_replace(['+', '/', '='], ['-', '_', ''], $data);
        return $data;
    }

    /**
     * Decode the safeBase64Encode() of the string values
     *
     * @see safeBase64Encode()
     *
     * @param  string $string
     * @return string
     */
    public static function safeBase64Decode($string)
    {
        $data = str_replace(['-', '_'], ['+', '/'], $string);
        $mod4 = strlen($data) % 4;
        if ($mod4) {
            $data .= substr('====', $mod4);
        }
        return base64_decode($data);
    }

    /* --------------------------------------------------------------------------------*
     |                              Extended Helpers                                   |
     |---------------------------------------------------------------------------------|
     */

    /**
     * Rotate each string characters by n positions in ASCII table
     * To encode use positive n, to decode - negative.
     * With n = 13 (ROT13), encode and decode n can be positive.
     * @see  {@link http://php.net/str_rot13}
     *
     * @param  string  $string
     * @param  integer $n
     * @return string
     */
    public static function rotate($string, $n = 13)
    {
        if (!is_string($string)) {
            throw new \InvalidArgumentException(
                sprintf(
                    'Parameter 1 must be as string! %s given.',
                    gettype($string)
                )
            );
        }

        $length = strlen($string);
        $result = '';

        for ($i = 0; $i < $length; $i++) {
            $ascii = ord($string{$i});

            $rotated = $ascii;

            if ($ascii > 64 && $ascii < 91) {
                $rotated += $n;
                $rotated > 90 && $rotated += -90 + 64;
                $rotated < 65 && $rotated += -64 + 90;
            } elseif ($ascii > 96 && $ascii < 123) {
                $rotated += $n;
                $rotated > 122 && $rotated += -122 + 96;
                $rotated < 97 && $rotated  += -96 + 122;
            }

            $result .= chr($rotated);
        }

        return $result;
    }

    protected static function hashStringContainer($string)
    {
        $hash_algorithms = hash_algos();
        $priority = [
            'sha512',
            'sha384',
            'ripemd320',
            'sha256',
            'ripemd256',
            'sha224',
            'ripemd160',
            'sha1',
        ];
        $chosen_algorithm = null;
        foreach ($priority as $algorithm) {
            if (in_array($algorithm, $hash_algorithms)) {
                $chosen_algorithm = $algorithm;
                break;
            }
        }
        if (!$chosen_algorithm) {
            $hash = sha1($string);
        } else {
            $hash = hash($chosen_algorithm, $string);
        }

        return "$hash";
    }

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

        $key       = pack('H*', self::hashStringContainer($serialize_key));
        return [
            $serialize_key,
            self::safeBase64Encode(str_pad($key, 24, "\0", STR_PAD_RIGHT))
        ];
    }


    /* --------------------------------------------------------------------------------*
     |                              Encryption openSSL                                 |
     |---------------------------------------------------------------------------------|
     */

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
        $iv = self::safeBase64Encode($crypt_arr[2]);

        $json_value = json_encode([
            'micro'  => $microtime,
            'method' => $crypt_arr[1],
            'iv'     => $iv,
            'value'  => $crypt_arr[0],
        ]);

        // save as bse64 encode safe
        $crypt_text = trim(
            self::safeBase64Encode(
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
        $separator = self::safeBase64Encode(sha1($passKey[1]) . self::OPENSSL_MIDDLE);
        if (strlen($crypt_text) > $pos) {
            return substr_replace($crypt_text, $separator . $pos, $pos, 0);
        } else {
            return substr_replace($crypt_text, $separator . $pos, 2, 0);
        }
    }

    public static function decrypt($value, $hash = false)
    {
        if (!is_string($value) || strlen(trim($value)) < 4) {
            return null;
        }

        $passKey          = self::createPassKey($hash);
        $pos              = abs(round(strlen($passKey[0]) / 3));
        $the_val_pos      = (strlen($value) > $pos);
        $length_to_check  =  $the_val_pos ? $pos : 2;
        $separator_openssl= self::safeBase64Encode(sha1($passKey[1]) . self::OPENSSL_MIDDLE);
        $length           = strlen($separator_openssl . $pos);
        $string_to_check  = substr($value, $length_to_check, $length);

        if ($string_to_check != $separator_openssl . $pos) {
            $separator_middle = self::safeBase64Encode(sha1($passKey[1]) . self::STANDARD_MIDDLE);
            $length_2         = strlen($separator_middle . $pos);
            $string_to_check_2 = substr($value, $length_to_check, $length_2);
            if ($string_to_check_2 != $separator_middle . $pos) {
                return null;
            }

            return static::altDecrypt($value, $hash);
        }

        /**
         * Using Alternative Encryption
         * if openssl not loaded
         */
        if (! extension_loaded('openssl')) {
            return null;
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

        $value = self::safeBase64Decode($value);
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
        $iv     = self::safeBase64Decode($json_decode_value['iv']);
        unset($json_decode_info, $json_decode_value);

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
        $crypt_text = self::rotate($crypt_text, (strlen($hash) % 13));
        $add = 0;
        $iv = self::safeBase64Decode(sha1($method . @time()));
        if (strlen($hash) < strlen($crypt_text)) {
            $crypt_text = substr_replace($crypt_text, $iv, strlen($hash), 0);
        } else {
            $crypt_text = $crypt_text . $iv;
        }
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
            self::safeBase64Encode($ascii),
            $method, // for what?
            $iv
        ];
    }

    /**
     * Decrypt string container crypt text
     *
     * @param string $hash
     * @param string $crypt_text
     * @param string $method
     * @param string $iv
     * @return null|string
     */
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
        $crypt_text = self::safeBase64Decode($crypt_text);
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
        if (strlen($hash) < strlen($unpack)) {
            $sub_iv = substr($unpack, strlen($hash), strlen($iv));
        } else {
            $sub_iv = substr($unpack, -strlen($iv));
        }
        if ($sub_iv !== $iv) {
            return null;
        }
        $crypt_text = substr_replace($unpack, '', strlen($hash), strlen($iv));
        return self::rotate($crypt_text, -(strlen($hash) % 13));
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
        $iv = self::safeBase64Encode($method . $crypt_arr[2]);
        $json_value = json_encode([
            'micro'  => $microtime,
            'method' => $crypt_arr[1],
            'iv'     => $iv,
            'value'  => $crypt_arr[0],
        ]);

        // save as bse64 encode safe
        $crypt_text = trim(
            self::safeBase64Encode(
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
        $separator = self::safeBase64Encode(sha1($passKey[1]) . self::STANDARD_MIDDLE);
        if (strlen($crypt_text) > $pos) {
            return substr_replace($crypt_text, $separator . $pos, $pos, 0);
        } else {
            return substr_replace($crypt_text, $separator . $pos, 2, 0);
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
        $separator_middle = self::safeBase64Encode(sha1($passKey[1]) . self::STANDARD_MIDDLE);
        $length           = strlen($separator_middle . $pos);
        $string_to_check  = substr($value, $length_to_check, $length);

        /**
         * Check if use OpenSSSL encryption or invalid value
         */
        if ($string_to_check != $separator_middle . $pos) {
            $separator_openssl= self::safeBase64Encode(sha1($passKey[1]) . self::OPENSSL_MIDDLE);
            $length_2         = strlen($separator_openssl . $pos);
            $string_to_check_2 = substr($value, $length_to_check, $length_2);
            if (!extension_loaded('openssl')
                || $string_to_check_2 != $separator_openssl . $pos) {
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

        $value = self::safeBase64Decode($value);
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
        $iv     = self::safeBase64Decode($json_decode_value['iv']);
        unset($json_decode_info, $json_decode_value);

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
