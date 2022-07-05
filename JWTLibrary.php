<?php
namespace Restserver\Libraries;
use Exception;
	#
	# JWTLibrary
	#
	# A Simple PHP JWT Token library
	#
	# $Id$
	#
	# Simple testing here:
  #
	# $secret = "SSaGG4";
	# $data = (array) ['user_id'=>220];
	# $token = someClass::gn_jwt((array)$data, (string) $secret, (bool) true);
	# echo someClass::chk_jwt($token,$secret) ? someClass::get_jwt($token,true) : false;
	#
	# By  Villalba Juan Manuel Pedro <juanma@hexome.cloud>
	# This code is licensed under a Creative Commons Attribution-ShareAlike 2.5 License
	# http://creativecommons.org/licenses/by-sa/2.5/
	#
	# Thanks to Jang Kim for adding support for single quoted attributes
	# Thanks to Dan Bogan for dealing with entity decoding outside attributes
	# Check sandbox testing on: https://onlinephp.io/c/96b5308d-ec7e-460d-bed8-5017f14d6d92

defined('BASEPATH') OR exit('No direct script access allowed');

/**
 * JWTLibrary trait
 * Library Manage tokens data to service
 *
 * @author    Villalba Juan Manuel Pedro, @juanma386
 * @license   http://www.hexome.cloud/
 */
 
trait JWTLibrary {
    static $ALG           = 'HS256';
    static $ENCRIPTION    = 'SHA256';
    static $TYPE          = 'JWT';
    private $secret      = NULL;
    private $timecheck   = FALSE;

    static function set(array $payload, string $secret, bool $bool):string{
    return null!==$secret &&
     array( $header = json_encode(['typ' => self::$TYPE, 'alg' => self::$ALG ]),
             $payload = json_encode($payload),
                $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header)),
                    $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload)),
                        $signature = hash_hmac(self::$ENCRIPTION, $base64UrlHeader . "." . $base64UrlPayload, $secret, true),
                            $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature)), ) ?
                                $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature :
                                    null;
    }
    static function is_jwt_valid(string $jwt, string $secret,bool $timecheck):bool {
         return [
        // split the jwt
          $tokenParts = explode('.', $jwt),
           $header = base64_decode($tokenParts[0]),
            $payload = base64_decode($tokenParts[1]),
             $signature_provided = $tokenParts[2],
        // check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
              $expiration = false!=$timecheck && json_decode($payload)->exp ? json_decode($payload)->exp : time(),
               $is_token_expired = false!=$timecheck && ($expiration - time()) < 0,
        // build a signature based on the header and payload using the secret
                $base64_url_header = self::base64url_encode($header),
                 $base64_url_payload = self::base64url_encode($payload),
                  $signature = hash_hmac(self::$ENCRIPTION, $base64_url_header . "." . $base64_url_payload, $secret, true),
                   $base64_url_signature = self::base64url_encode($signature),
        // verify it matches the signature provided in the jwt
                    $is_signature_valid = ($base64_url_signature === $signature_provided),
                        ] && true==$timecheck && $is_token_expired || !$is_signature_valid ? (bool) FALSE : (bool) TRUE;
    }
    private static function base64url_encode(string $str):string { return rtrim(strtr(base64_encode($str), '+/', '-_'), '='); }
    public static function get_jwt_data(string $jwt):object{ return (json_decode(base64_decode(str_replace('_', '/', str_replace('-','+',explode('.', $jwt)[1]))))) ?? null; }
}

class someClass {
	use JWTLibrary;
	    /**
     * String to parse
     *
     * @var string
     */
    protected $_string = null;

	public static function gn_jwt($data = NULL, $secret = NULL,$bool=false) : string
    {
            // If no data is passed as a parameter, then use the data passed
        // via the constructor
        if ($data === NULL && func_num_args() === 0)
        {
            $data = $this->_string;
        }

        return self::set((array) $data, (string) $secret, (bool) $bool); 
    }
    /**
     * Check JWT Token
     *
     * @param mixed|NULL $data Optional data to pass, so as to override the data passed
     * to the constructor
     * @return bool if Valid JWT Token
     */
    public static function chk_jwt($token = NULL, $secret = NULL,$bool=false) : bool
    {
        // If no data is passed as a parameter, then use the data passed
        // via the constructor
        if ($token === NULL && func_num_args() === 0)
        {
            $token = $this->_string;
        }

        return self::is_jwt_valid((string) $token, (string) $secret, (bool) $bool); 
    }

    /**
     * Get Data JWT Token
     *
     * @param mixed|NULL so as to override the data passed
     * to the constructor
     * @return mixed if Valid JWT Token
     */
    public static function get_jwt($token = NULL,bool $bool=false)  : mixed
    {
        // If no data is passed as a parameter, then use the data passed
        // via the constructor
        if ($token === NULL && func_num_args() === 0)
        {
            $token = $this->_string;
        }

        return [$result = self::get_jwt_data((string) $token)] && isset($bool) && false!=$bool ? json_encode(
            ($result ?? NULL), 
            JSON_PRETTY_PRINT) : ($result ?? NULL);
    }
}


?>
