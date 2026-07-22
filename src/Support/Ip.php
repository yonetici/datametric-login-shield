<?php
/**
 * Client IP resolution.
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

/**
 * Resolves the client IP address safely.
 *
 * By default only REMOTE_ADDR is trusted (spoof-proof). Sites behind a trusted
 * reverse proxy can opt into X-Forwarded-For via the `dls_trusted_proxy` filter.
 */
class Ip {

	/**
	 * Get the validated client IP, or an empty string if none is valid.
	 *
	 * @return string
	 */
	public static function get() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

		/**
		 * Trust the X-Forwarded-For header (only enable behind a proxy you control).
		 *
		 * @param bool $trust Default false.
		 */
		if ( apply_filters( 'dls_trusted_proxy', false ) && ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$forwarded = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
			$parts     = explode( ',', $forwarded );
			$candidate = trim( $parts[0] );

			if ( self::is_valid( $candidate ) ) {
				$ip = $candidate;
			}
		}

		return self::is_valid( $ip ) ? $ip : '';
	}

	/**
	 * Whether a string is a valid IPv4/IPv6 address.
	 *
	 * @param string $ip Candidate.
	 *
	 * @return bool
	 */
	public static function is_valid( $ip ) {
		return (bool) filter_var( $ip, FILTER_VALIDATE_IP );
	}

	/**
	 * Anonymize an IP for privacy (mask the last IPv4 octet / IPv6 suffix).
	 *
	 * @param string $ip IP address.
	 *
	 * @return string
	 */
	public static function anonymize( $ip ) {
		if ( ! self::is_valid( $ip ) ) {
			return '';
		}

		if ( false !== strpos( $ip, ':' ) ) {
			// IPv6: keep the first block only.
			$blocks = explode( ':', $ip );

			return $blocks[0] . '::';
		}

		$octets = explode( '.', $ip );
		if ( count( $octets ) === 4 ) {
			$octets[3] = '0';

			return implode( '.', $octets );
		}

		return $ip;
	}
}
