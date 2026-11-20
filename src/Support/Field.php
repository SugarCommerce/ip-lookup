<?php
/**
 * Field
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Support;

/**
 * Class Field
 *
 * One field of a provider's answer, read as the type it should be.
 *
 * An answer is someone else's JSON. A field can turn up as a list where a
 * string was promised, or a number where a flag was: returned as it came
 * from a method typed `?string`, that is a TypeError, and a fraud check on
 * the checkout becomes a fatal error on the checkout. Each reader here
 * gives the type or null, never anything else.
 *
 * @since 1.0.0
 */
final class Field {

	/**
	 * The most of a provider's message an error carries.
	 */
	private const int MESSAGE_LENGTH = 300;

	/**
	 * Text, or null when it is missing, empty or not a single value.
	 *
	 * @since 1.0.0
	 *
	 * @param mixed $value The field.
	 *
	 * @return string|null
	 */
	public static function text( mixed $value ): ?string {
		if ( ! is_scalar( $value ) || is_bool( $value ) ) {
			return null;
		}

		$value = (string) $value;

		return '' === $value ? null : $value;
	}

	/**
	 * A whole number, or null when it is not a number.
	 *
	 * @since 1.0.0
	 *
	 * @param mixed $value The field.
	 *
	 * @return int|null
	 */
	public static function int( mixed $value ): ?int {
		return is_numeric( $value ) ? (int) (float) $value : null;
	}

	/**
	 * A number, or null when it is not one.
	 *
	 * @since 1.0.0
	 *
	 * @param mixed $value The field.
	 *
	 * @return float|null
	 */
	public static function float( mixed $value ): ?float {
		return is_numeric( $value ) ? (float) $value : null;
	}

	/**
	 * A list or a map, or null when it is not one.
	 *
	 * @since 1.0.0
	 *
	 * @param mixed $value The field.
	 *
	 * @return array|null
	 */
	public static function map( mixed $value ): ?array {
		return is_array( $value ) ? $value : null;
	}

	/**
	 * A web address a page can link to, or null.
	 *
	 * Only `http` and `https`, with a host: a provider's `javascript:` or
	 * `data:` URL is no URL, so a page that prints it as a link cannot be
	 * made to run script.
	 *
	 * @since 1.0.0
	 *
	 * @param mixed $value The field.
	 *
	 * @return string|null
	 */
	public static function url( mixed $value ): ?string {
		$value = self::text( $value );

		if ( null === $value ) {
			return null;
		}

		$value  = trim( $value );
		$scheme = strtolower( (string) parse_url( $value, PHP_URL_SCHEME ) );
		$host   = (string) parse_url( $value, PHP_URL_HOST );

		if ( ! in_array( $scheme, array( 'http', 'https' ), true ) || '' === $host || 1 === preg_match( '/[\s"\'<>`]/', $value ) ) {
			return null;
		}

		return $value;
	}

	/**
	 * A provider's message, fit for an error: plain text, one line, clipped.
	 *
	 * @since 1.0.0
	 *
	 * @param mixed  $value    The field.
	 * @param string $fallback What to say when there is no message.
	 *
	 * @return string
	 */
	public static function message( mixed $value, string $fallback ): string {
		$value = self::text( $value );

		if ( null === $value ) {
			return $fallback;
		}

		$value = trim( (string) preg_replace( '/\s+/', ' ', wp_strip_all_tags( $value ) ) );

		if ( '' === $value ) {
			return $fallback;
		}

		return mb_strlen( $value ) > self::MESSAGE_LENGTH ? mb_substr( $value, 0, self::MESSAGE_LENGTH ) . '…' : $value;
	}
}
