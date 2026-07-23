<?php
/**
 * Pure-PHP TOTP (RFC 6238) helper — no external service.
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

/**
 * Generates and verifies time-based one-time passwords compatible with Google
 * Authenticator, Authy, 1Password, etc.
 */
class Totp {

	const DIGITS = 6;
	const PERIOD = 30;
	const B32     = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Generate a new Base32 secret.
	 *
	 * @param int $bytes Entropy in bytes (default 20 = 160 bits).
	 *
	 * @return string
	 */
	public static function generate_secret( $bytes = 20 ) {
		$binary = '';
		for ( $i = 0; $i < $bytes; $i++ ) {
			$binary .= chr( random_int( 0, 255 ) );
		}

		return self::base32_encode( $binary );
	}

	/**
	 * Compute the TOTP code for a secret at a given time.
	 *
	 * @param string   $secret    Base32 secret.
	 * @param int|null $timestamp Unix time (defaults to now).
	 *
	 * @return string Zero-padded 6-digit code.
	 */
	public static function code( $secret, $timestamp = null ) {
		$timestamp = ( null === $timestamp ) ? time() : (int) $timestamp;
		$counter   = (int) floor( $timestamp / self::PERIOD );

		$key = self::base32_decode( $secret );
		if ( '' === $key ) {
			return '';
		}

		// 8-byte big-endian counter.
		$binary = pack( 'N*', 0 ) . pack( 'N*', $counter );
		$hash   = hash_hmac( 'sha1', $binary, $key, true );

		$offset = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0F;
		$part   = substr( $hash, $offset, 4 );
		$value  = unpack( 'N', $part );
		$number = $value[1] & 0x7FFFFFFF;

		return str_pad( (string) ( $number % ( 10 ** self::DIGITS ) ), self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Verify a submitted code against the secret, allowing +/- $window steps.
	 *
	 * @param string $secret Base32 secret.
	 * @param string $input  Submitted code.
	 * @param int    $window Number of 30s steps of clock drift to allow.
	 *
	 * @return bool
	 */
	public static function verify( $secret, $input, $window = 1 ) {
		$input = preg_replace( '/\D/', '', (string) $input );
		if ( strlen( $input ) !== self::DIGITS ) {
			return false;
		}

		$now = time();
		for ( $i = -$window; $i <= $window; $i++ ) {
			$candidate = self::code( $secret, $now + ( $i * self::PERIOD ) );
			if ( '' !== $candidate && hash_equals( $candidate, $input ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Build an otpauth:// provisioning URI for QR codes / manual import.
	 *
	 * @param string $secret  Base32 secret.
	 * @param string $account Account label (e.g. user email).
	 * @param string $issuer  Issuer label (e.g. site name).
	 *
	 * @return string
	 */
	public static function provisioning_uri( $secret, $account, $issuer ) {
		return sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d',
			rawurlencode( $issuer ),
			rawurlencode( $account ),
			rawurlencode( $secret ),
			rawurlencode( $issuer ),
			self::DIGITS,
			self::PERIOD
		);
	}

	/**
	 * RFC 4648 Base32 encode.
	 *
	 * @param string $data Raw bytes.
	 *
	 * @return string
	 */
	public static function base32_encode( $data ) {
		if ( '' === $data ) {
			return '';
		}

		$bits = '';
		foreach ( str_split( $data ) as $char ) {
			$bits .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
		}

		$output = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$chunk    = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
			$output  .= self::B32[ bindec( $chunk ) ];
		}

		return $output;
	}

	/**
	 * RFC 4648 Base32 decode. Returns '' on invalid input.
	 *
	 * @param string $data Base32 string.
	 *
	 * @return string
	 */
	public static function base32_decode( $data ) {
		$data = strtoupper( preg_replace( '/[^A-Z2-7]/', '', (string) $data ) );
		if ( '' === $data ) {
			return '';
		}

		$bits = '';
		foreach ( str_split( $data ) as $char ) {
			$index = strpos( self::B32, $char );
			if ( false === $index ) {
				return '';
			}
			$bits .= str_pad( decbin( $index ), 5, '0', STR_PAD_LEFT );
		}

		$output = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( 8 === strlen( $byte ) ) {
				$output .= chr( bindec( $byte ) );
			}
		}

		return $output;
	}
}
