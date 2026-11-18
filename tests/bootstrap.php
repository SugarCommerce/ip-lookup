<?php
/**
 * PHPUnit bootstrap.
 *
 * There is no WordPress to load: the core functions the library and its
 * dependencies touch are stubbed here, and the HTTP API answers from a
 * queue the tests fill (Support\FakeHttp).
 *
 * @package SugarCommerce\IpLookup
 */

declare( strict_types=1 );

use SugarCommerce\IpLookup\Tests\Support\FakeHttp;

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', dirname( __DIR__ ) . '/' );
}

if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
	define( 'MINUTE_IN_SECONDS', 60 );
	define( 'HOUR_IN_SECONDS', 3600 );
	define( 'DAY_IN_SECONDS', 86400 );
}

require_once dirname( __DIR__ ) . '/vendor/autoload.php';

/**
 * Transients, with when each expires (0 = never), and the clock they expire by.
 *
 * @var array<string, array{value: mixed, expires: int}>
 */
$GLOBALS['ipl_transients'] = array();
$GLOBALS['ipl_now']        = 1_800_000_000;

/**
 * Options, and whether transients live in a persistent object cache
 * rather than the options table (so a LIKE over the table finds none).
 *
 * @var array<string, mixed>
 */
$GLOBALS['ipl_options']      = array();
$GLOBALS['ipl_object_cache'] = false;

/**
 * Forget every transient and queued answer.
 *
 * @return void
 */
function ipl_reset(): void {
	$GLOBALS['ipl_transients'] = array();
	$GLOBALS['ipl_now']        = 1_800_000_000;
	$GLOBALS['ipl_options']      = array();
	$GLOBALS['ipl_object_cache'] = false;
	$_SERVER                   = array();
	FakeHttp::reset();
}

/**
 * Move the transient clock on.
 *
 * @param int $seconds Seconds.
 *
 * @return void
 */
function ipl_advance( int $seconds ): void {
	$GLOBALS['ipl_now'] += $seconds;
}

if ( ! class_exists( 'WP_Error' ) ) {
	/**
	 * Core's error object, near enough.
	 */
	class WP_Error {

		/**
		 * @param string $code    Code.
		 * @param string $message Message.
		 * @param mixed  $data    Data.
		 */
		public function __construct( public string $code = '', public string $message = '', public mixed $data = '' ) {}

		/**
		 * @return string
		 */
		public function get_error_code(): string {
			return $this->code;
		}

		/**
		 * @return string
		 */
		public function get_error_message(): string {
			return $this->message;
		}

		/**
		 * @return mixed
		 */
		public function get_error_data(): mixed {
			return $this->data;
		}
	}
}

/**
 * @param mixed $thing Anything.
 *
 * @return bool
 */
function is_wp_error( $thing ): bool {
	return $thing instanceof WP_Error;
}

/**
 * @param string $text   Text.
 * @param string $domain Domain.
 *
 * @return string
 */
function __( $text, $domain = 'default' ) {
	return $text;
}

/**
 * @param string $text   Text.
 * @param string $domain Domain.
 *
 * @return string
 */
function esc_html__( $text, $domain = 'default' ) {
	return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
}

/**
 * @param string $text Text.
 *
 * @return string
 */
function esc_html( $text ) {
	return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
}

/**
 * @param string $single Singular.
 * @param string $plural Plural.
 * @param int    $count  Count.
 *
 * @return string
 */
function _n( $single, $plural, $count ) {
	return 1 === (int) $count ? $single : $plural;
}

/**
 * @param float $number   Number.
 * @param int   $decimals Decimals.
 *
 * @return string
 */
function number_format_i18n( $number, $decimals = 0 ) {
	return number_format( (float) $number, (int) $decimals );
}

/**
 * @param mixed $value Value.
 *
 * @return mixed
 */
function wp_unslash( $value ) {
	return is_string( $value ) ? stripslashes( $value ) : $value;
}

/**
 * @param string $text Text.
 *
 * @return string
 */
function sanitize_text_field( $text ) {
	return trim( preg_replace( '/[\r\n\t ]+/', ' ', strip_tags( (string) $text ) ) );
}

/**
 * @param string $text Text.
 *
 * @return string
 */
function wp_strip_all_tags( $text ) {
	return trim( strip_tags( (string) $text ) );
}

/**
 * @param mixed $value Value.
 *
 * @return string|false
 */
function wp_json_encode( $value ) {
	return json_encode( $value );
}

/**
 * @param array $args     Arguments.
 * @param array $defaults Defaults.
 *
 * @return array
 */
function wp_parse_args( $args, $defaults = array() ) {
	return array_merge( (array) $defaults, (array) $args );
}

/**
 * @param array  $args Query arguments.
 * @param string $url  URL.
 *
 * @return string
 */
function add_query_arg( array $args, string $url ) {
	return $url . ( str_contains( $url, '?' ) ? '&' : '?' ) . http_build_query( $args );
}

/**
 * @param string $email Address.
 *
 * @return string|false
 */
function is_email( $email ) {
	return false !== filter_var( $email, FILTER_VALIDATE_EMAIL ) ? $email : false;
}

/**
 * @param string $show What.
 *
 * @return string
 */
function get_bloginfo( $show = '' ) {
	return 'name' === $show ? 'Test <b>Shop</b>' : '';
}

/**
 * @return string
 */
function get_locale() {
	return 'en_US';
}

/**
 * @param string $hook Hook.
 *
 * @return bool
 */
function add_action( ...$args ) {
	return true;
}

/**
 * @return bool
 */
function add_filter( ...$args ) {
	return true;
}

/**
 * @param string $hook  Hook.
 * @param mixed  $value Value.
 *
 * @return mixed
 */
function apply_filters( $hook, $value ) {
	return $value;
}

/**
 * @return void
 */
function do_action( ...$args ) {}

/**
 * @param string $name    Option.
 * @param mixed  $default Fallback.
 *
 * @return mixed
 */
function get_option( $name, $default = false ) {
	return array_key_exists( $name, $GLOBALS['ipl_options'] ) ? $GLOBALS['ipl_options'][ $name ] : $default;
}

/**
 * @param string    $name     Option.
 * @param mixed     $value    Value.
 * @param bool|null $autoload Autoload.
 *
 * @return bool
 */
function update_option( $name, $value, $autoload = null ) {
	$GLOBALS['ipl_options'][ $name ] = $value;

	return true;
}

/**
 * @param string $key Key.
 *
 * @return mixed
 */
function get_transient( $key ) {
	$entry = $GLOBALS['ipl_transients'][ $key ] ?? null;

	if ( null === $entry ) {
		return false;
	}

	if ( 0 !== $entry['expires'] && $entry['expires'] <= $GLOBALS['ipl_now'] ) {
		unset( $GLOBALS['ipl_transients'][ $key ] );

		return false;
	}

	return $entry['value'];
}

/**
 * @param string $key        Key.
 * @param mixed  $value      Value.
 * @param int    $expiration Seconds.
 *
 * @return bool
 */
function set_transient( $key, $value, $expiration = 0 ) {
	$GLOBALS['ipl_transients'][ $key ] = array(
		'value'   => $value,
		'expires' => $expiration > 0 ? $GLOBALS['ipl_now'] + (int) $expiration : 0,
	);

	return true;
}

/**
 * @param string $key Key.
 *
 * @return bool
 */
function delete_transient( $key ) {
	$found = isset( $GLOBALS['ipl_transients'][ $key ] );
	unset( $GLOBALS['ipl_transients'][ $key ] );

	return $found;
}

/**
 * @param string $url  URL.
 * @param array  $args Arguments.
 *
 * @return array|WP_Error
 */
function wp_remote_get( $url, $args = array() ) {
	return FakeHttp::respond( 'GET', $url, $args );
}

/**
 * @param string $url  URL.
 * @param array  $args Arguments.
 *
 * @return array|WP_Error
 */
function wp_remote_post( $url, $args = array() ) {
	return FakeHttp::respond( 'POST', $url, $args );
}

/**
 * @param array|WP_Error $response Response.
 *
 * @return int|string
 */
function wp_remote_retrieve_response_code( $response ) {
	return is_array( $response ) ? $response['response']['code'] : '';
}

/**
 * @param array|WP_Error $response Response.
 *
 * @return string
 */
function wp_remote_retrieve_body( $response ) {
	return is_array( $response ) ? $response['body'] : '';
}

/**
 * The options table, for clear_cache() with no key.
 */
$GLOBALS['wpdb'] = new class() {

	/**
	 * @var string
	 */
	public string $options = 'wp_options';

	/**
	 * @param string $text Text.
	 *
	 * @return string
	 */
	public function esc_like( $text ) {
		return addcslashes( (string) $text, '_%\\' );
	}

	/**
	 * @param string $query Query.
	 * @param mixed  ...$args Arguments.
	 *
	 * @return string
	 */
	public function prepare( $query, ...$args ) {
		return (string) $args[0];
	}

	/**
	 * The transient rows whose names match a prepared LIKE.
	 *
	 * @param string $like The LIKE pattern, as prepare() left it.
	 *
	 * @return string[]
	 */
	public function get_col( $like ) {
		$prefix = stripslashes( substr( $like, 0, -1 ) );
		$names  = array();

		if ( $GLOBALS['ipl_object_cache'] ) {
			return $names;
		}

		foreach ( array_keys( $GLOBALS['ipl_transients'] ) as $key ) {
			if ( str_starts_with( '_transient_' . $key, $prefix ) ) {
				$names[] = '_transient_' . $key;
			}
		}

		return $names;
	}
};

/**
 * @param string $text Text.
 *
 * @return string
 */
function wp_check_invalid_utf8( $text ) {
	return mb_check_encoding( (string) $text, 'UTF-8' ) ? (string) $text : '';
}

/**
 * Registered post types, for sugarcommerce/conditions' sets.
 *
 * @var array<string, array>
 */
$GLOBALS['ipl_post_types'] = array();

/**
 * @param string $post_type Post type.
 *
 * @return bool
 */
function post_type_exists( $post_type ) {
	return isset( $GLOBALS['ipl_post_types'][ $post_type ] );
}

/**
 * @param string $post_type Post type.
 * @param array  $args      Arguments.
 *
 * @return object
 */
function register_post_type( $post_type, $args = array() ) {
	$GLOBALS['ipl_post_types'][ $post_type ] = $args;

	return (object) $args;
}

/**
 * @return bool
 */
function register_post_meta( ...$args ) {
	return true;
}

/**
 * @return void
 */
function add_meta_box( ...$args ) {}

/**
 * @return bool
 */
function register_rest_route( ...$args ) {
	return true;
}
