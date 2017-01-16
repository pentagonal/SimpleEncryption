<?php
/**
 * Pentagonal Encryption
 * This Library create encryption string and reverse it using mCrypt if possible
 *     if mCrypt not exists wil be use alternative encryption
 *     decryption will be check string as characters sign.
 *
 * @copyright   Copyright (c) 2015 awan
 * @copyright   Copyright (c) 2017 pentagonal
 * @link        https://github.com/pentagonal
 * @version     1.1.0
 * @author      awan <nawa@yahoo.com>
 * @author      pentagonal <org@pentagonal.org>
 * @package     pentagonal\SimpleEncryption
 * @license     GPLv3 or later <https://www.gnu.org/licenses/gpl-3.0.txt>
 */

namespace Pentagonal\SimpleEncryption;

class EncryptionTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Default salt
     * @var string
     */
    public $salt = 'salt';

    /**
     * Default Test String to encrypt
     * @var string
     */
    public $string_encrypt = 'test';

    /**
     * Using default mcrypt Encryption
     * @return string
     */
    public function encryptionDefault()
    {
        return Encryption::encrypt($this->string_encrypt);
    }

    /**
     * Using default mcrypt Encryption with salt key
     * @return string
     */
    public function encryptionDefaultWithSalt()
    {
        return Encryption::encrypt($this->string_encrypt, $this->salt);
    }

    /**
     * Using Alternative Encryption
     * @return string
     */
    public function encryptionAlternative()
    {
        return Encryption::altEncrypt($this->string_encrypt);
    }

    /**
     * Using Alternative Encryption with salt
     * @return string
     */
    public function encryptionAlternativeWithSalt()
    {
        return Encryption::altEncrypt($this->string_encrypt, $this->salt);
    }

    /**
     * Decrypt the default encryption
     */
    public function decryptionDefault()
    {
        return Encryption::decrypt(
            $this->encryptionDefault()
        );
    }

    /**
     * Decrypt the alternative encryption
     */
    public function decryptionAlternative()
    {
        return Encryption::decrypt(
            $this->encryptionAlternative()
        );
    }

    /**
     * Decrypt the default encryption with salt
     */
    public function decryptionDefaultWithSalt()
    {
        return Encryption::decrypt(
            $this->encryptionDefaultWithSalt(),
            $this->salt
        );
    }

    /**
     * Decrypt the alternative encryption with salt
     */
    public function decryptionAlternativeWithSalt()
    {
        return Encryption::decrypt(
            $this->encryptionAlternativeWithSalt(),
            $this->salt
        );
    }

    /**
     * Test Decryption Equalities
     */
    public function testDecryptionAllEqualities()
    {
        $decrypt1 = $this->decryptionDefault();
        $decrypt2 = $this->decryptionAlternative();
        $decrypt3 = $this->decryptionDefaultWithSalt();
        $decrypt4 = $this->decryptionAlternativeWithSalt();

        /**
         * Asserting Equals
         */
        $this->assertEquals(
            $decrypt1,
            $this->string_encrypt
        );

        /**
         * Asserting Equals
         */
        $this->assertEquals(
            $decrypt1,
            $decrypt2
        );

        /**
         * Asserting Equals
         */
        $this->assertEquals(
            $decrypt1,
            $decrypt3
        );

        /**
         * Asserting Equals
         */
        $this->assertEquals(
            $decrypt1,
            $decrypt4
        );
    }

    /**
     * Invalid decryption
     * @return null
     */
    public function testDecryptionNull()
    {
        $decrypt = Encryption::decrypt(
            $this->encryptionAlternativeWithSalt(),
            'invalid salt'
        );

        /**
         * Asserting Null
         */
        $this->assertNull(
            $decrypt
        );

        return $decrypt;
    }

    /**
     * Test Not equalities
     */
    public function testNotEquals()
    {
        $this->assertNotEquals(
            $this->encryptionAlternativeWithSalt(),
            $this->testDecryptionNull()
        );
    }
}
