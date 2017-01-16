<?php
namespace Pentagonal\SimpleEncryption\Cryptography;

/**
 * Hash sha256 hash algorithm
 *
 * Class sha256
 * @package Pentagonal\SimpleEncryption\Cryptography
 * @copyright   Copyright (c) 2017 Pentagonal
 * @link        https://github.com/pentagonal
 * @version     1.0.0
 * @author      pentagonal <org@pentagonal.org>
 * @license GPLv3 or later <https://www.gnu.org/licenses/gpl-3.0.txt>
 */
class Sha256 extends HashUtil
{
    /* --------------------------------------------------------------------------------*
     |                              Class Properties                                   |
     |---------------------------------------------------------------------------------|
     */

    /**
     * @var array
     */
    private $x_sha256_record = [];

    /**
     * @var Sha256
     */
    private static $instance;

    /* --------------------------------------------------------------------------------*
     |                                Class Method                                     |
     |---------------------------------------------------------------------------------|
     */

    /**
     * PHP5 Constructor
     * Doing add parameters to make hash echoing result
     *
     * @param string $str result hash
     */
    public function __construct($str = null)
    {
        self::$instance = $this;
        ! is_null($str) && $this->x_sha256_record[$str] = self::hash($str);
    }

    /**
     * Static Singleton
     * @return Sha256
     */
    public static function getInstance()
    {
        if (!self::$instance) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Doing hash
     *
     * @param  string $string string to hash
     * @return string         hash result
     */
    public static function hash($string)
    {
        static $valid_hash = null;
        if ($valid_hash === null) {
            $valid_hash = function_exists('hash') && (in_array('sha256', hash_algos()));
        }

        /**
         * Fallback hash('sha256', [(string) string]);
         */
        if ($valid_hash) {
            return hash('sha256', $string);
        }

        if (is_array($string) || is_object($string)) {
            $type   = gettype($string);
            $caller =  next(debug_backtrace());
            $error['line']  = $caller['line'];
            $error['file']  = strip_tags($caller['file']);
            trigger_error(
                "sha1() expects parameter 1 to be string, "
                . $type
                . " given in <b>{$error['file']}</b> on line <b>{$error['line']}</b><br />\n",
                E_USER_ERROR
            );

            return null;
        }

        // convert into string
        $string = "{$string}";
        /**
         * Instance Application
         * @var object
         */
        $instance = self::getInstance();
        $key = md5($string);
        if (isset($instance->x_sha256_record[$key])) {
            return $instance->x_sha256_record[$key];
        }

        /**
         * SHA-256 Constants
         * sequence of 64 constant 32-bit words representing the first thirty-two bits
         * of the fractional parts of the cube roots of the first 64 prime numbers.
         * @var  array
         */
        $keyState64 = [
                   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                   0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                   0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                   0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                   0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                   0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                   0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                   0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                   0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
        /**
         * [$state8 description]
         * @var array
         */
        $state8 = [
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19
        ];
        /**
         *  Parsing the Padded Message (Break into N 512-bit blocks)
         * @var array
         */
        $string_split = str_split(
            $instance->charPad($string), // Pre-processing: Padding the string
            64
        );

        // loop through message blocks and compute hash. ( For i=1 to N : )
        for ($i = 0; $i < count($string_split); $i++) {
            // Break input block into 16 32-bit words (message schedule prep)
            $MI = parent::byte2intSplit($string_split[$i]);
            // Initialize working variables
            $a = $state8[0];
            $b = $state8[1];
            $c = $state8[2];
            $d = $state8[3];
            $e = $state8[4];
            $f = $state8[5];
            $g = $state8[6];
            $h = $state8[7];
            $W = [];
            // Compute the hash and update
            for ($t = 0; $t < 16; $t++) {
                // Prepare the first 16 message schedule values as we loop
                $W[$t] = $MI[$t];
                $t1 = ($e & $f) ^ ((~$e) & $g); //$instance->Ch($e, $f, $g);
                $t1 = $instance->add(
                    $instance->add(
                        $h,
                        ($instance->rotr($e, 6)^$instance->rotr($e, 11)^$instance->rotr($e, 25)) //$instance->Sigma1($e)
                    ),
                    $t1
                );
                // Compute hash
                $t1 = $instance->add(
                    $instance->add(
                        $t1,
                        $keyState64[$t]
                    ),
                    $W[$t]
                );
                $t2 = $instance->add(
                    ($instance->rotr($a, 2)^$instance->rotr($a, 13)^$instance->rotr($a, 22)), //$instance->Sigma0($a),
                    (($a & $b) ^ ($a & $c) ^ ($b & $c)) //$instance->Maj($a, $b, $c)
                );

                // Update working variables
                $h = $g;
                $g = $f;
                $f = $e;
                $e = $instance->add($d, $t1);
                $d = $c;
                $c = $b;
                $b = $a;
                $a = $instance->add($t1, $t2);
            }

            for (; $t < 64; $t++) {
                // Continue building the message schedule as we loop
                $s0 = $W[($t+1)&0x0F];
                $s0 =($instance->rotr($s0, 7)^$instance->rotr($s0, 18)^parent::zeroFill($s0, 3));
                $s1 = $W[($t+14)&0x0F];
                $s1 = $instance->rotr($s1, 17)^$instance->rotr($s1, 19)^parent::zeroFill($s1, 10);
                $W[$t&0xF] = $instance->add($W[$t&0xF], $s0);
                $W[$t&0xF] = $instance->add($W[$t&0xF], $s1);
                $W[$t&0xF] = $instance->add($W[$t&0xF], $W[($t+9)&0x0F]);

                // Compute hash
                $t1 = $instance->add($h, ($instance->rotr($e, 6)^$instance->rotr($e, 11)^$instance->rotr($e, 25)));
                $t1 = $instance->add($t1, (($e & $f) ^ ((~$e) & $g)));
                $t1 = $instance->add($t1, $keyState64[$t]);
                $t1 = $instance->add($t1, $W[$t&0xF]);
                $t2 = $instance->add(
                    ($instance->rotr($a, 2)^$instance->rotr($a, 13)^$instance->rotr($a, 22)),
                    ($a & $b) ^ ($a & $c) ^ ($b & $c)
                );

                // Update working variables
                $h = $g;
                $g = $f;
                $f = $e;
                $e = $instance->add($d, $t1);
                $d = $c;
                $c = $b;
                $b = $a;
                $a = $instance->add($t1, $t2);
            }

            $state8[0] = $instance->add($state8[0], $a);
            $state8[1] = $instance->add($state8[1], $b);
            $state8[2] = $instance->add($state8[2], $c);
            $state8[3] = $instance->add($state8[3], $d);
            $state8[4] = $instance->add($state8[4], $e);
            $state8[5] = $instance->add($state8[5], $f);
            $state8[6] = $instance->add($state8[6], $g);
            $state8[7] = $instance->add($state8[7], $h);
        }
        // Convert the 32-bit words into human readable hexadecimal format.
        $instance->x_sha256_record[$key] = sprintf(
            "%08x%08x%08x%08x%08x%08x%08x%08x",
            $state8[0],
            $state8[1],
            $state8[2],
            $state8[3],
            $state8[4],
            $state8[5],
            $state8[6],
            $state8[7]
        );
        $ret_val = $instance->x_sha256_record[$key];
        unset(
            $string,
            $W,
            $instance,
            $binStr,
            $keyState64,
            $string_split,
            $state8,
            $MI,
            $s0,
            $s1,
            $t1,
            $t2
        );
        return $ret_val;
    }
    /**
     * Do the SHA-256 Padding routine (make input a multiple of 512 bits)
     *
     * @param string $str string to padding
     *
     * @return string
     */
    private function charPad($str)
    {
        $l = strlen($str)*8;     // # of bits from input string
        $str .= "\x80";          // append the "1" bit followed by 7 0's
        $k = (512 - (($l + 8 + 64) % 512)) / 8;   // # of 0 bytes to append
        $k += 4;    // PHP String's will never exceed (2^31)-1, so 1st 32bits of
                    // the 64-bit value representing $l can be all 0's
        for ($x = 0; $x < $k; $x++) {
            $str .= "\0";
        }
        // append the last 32-bits representing the # of bits from input string ($l)
        $str .= chr((($l >> 24) & 0xFF));
        $str .= chr((($l >> 16) & 0xFF));
        $str .= chr((($l >> 8) & 0xFF));
        $str .= chr(($l & 0xFF));
        return $str;
    }

    /**
     * @param int $x
     * @param int $y
     *
     * @return int
     */
    private function add($x, $y)
    {
        $lsw = ($x & 65535) + ($y & 65535);
        $msw = ($x >> 16) + ($y >> 16) + ($lsw >> 16);
        return  ($msw << 16) | $lsw & 65535;
    }

    /**
     * @param int $x
     * @param int $n
     *
     * @return int
     */
    private function rotr($x, $n)
    {
        return (parent::zeroFill($x, $n) | ($x << (32-$n)));
    }

    /* --------------------------------------------------------------------------------*
     |                                Overloading                                      |
     |---------------------------------------------------------------------------------|
     */

    /**
     * Php5 Magic Method Echoing Object
     * @return string   end sha256 cache
     */
    public function __toString()
    {
        $return_value = end($this->x_sha256_record);
        return "{$return_value}";
    }

    /**
     * Destruct or end of object called & render
     */
    public function __destruct()
    {
        $this->x_sha256_record = [];
    }
}
