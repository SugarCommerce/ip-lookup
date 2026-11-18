<?php
/**
 * A stand-in for the WordPress HTTP API.
 *
 * @package SugarCommerce\IpLookup
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Tests\Support;

use WP_Error;

/**
 * Answers wp_remote_get() and wp_remote_post() from a queue, and keeps
 * every request made.
 */
final class FakeHttp {

	/**
	 * Answers waiting.
	 *
	 * @var array<int, array|WP_Error>
	 */
	private static array $queue = array();

	/**
	 * Requests made.
	 *
	 * @var array<int, array{method: string, url: string, args: array}>
	 */
	private static array $requests = array();

	/**
	 * Queue a JSON answer.
	 *
	 * @param mixed $data   What to encode.
	 * @param int   $status The status.
	 *
	 * @return void
	 */
	public static function json( mixed $data, int $status = 200 ): void {
		self::raw( (string) json_encode( $data ), $status );
	}

	/**
	 * Queue a raw answer.
	 *
	 * @param string $body   The body.
	 * @param int    $status The status.
	 *
	 * @return void
	 */
	public static function raw( string $body, int $status = 200 ): void {
		self::$queue[] = array(
			'response' => array( 'code' => $status ),
			'body'     => $body,
		);
	}

	/**
	 * Queue a transport failure.
	 *
	 * @return void
	 */
	public static function fail(): void {
		self::$queue[] = new WP_Error( 'http_request_failed', 'cURL error 28: Operation timed out' );
	}

	/**
	 * Answer a request.
	 *
	 * @param string $method The method.
	 * @param string $url    The URL.
	 * @param array  $args   The arguments.
	 *
	 * @return array|WP_Error
	 */
	public static function respond( string $method, string $url, array $args ): array|WP_Error {
		self::$requests[] = array(
			'method' => $method,
			'url'    => $url,
			'args'   => $args,
		);

		return array_shift( self::$queue ) ?? array(
			'response' => array( 'code' => 200 ),
			'body'     => '{}',
		);
	}

	/**
	 * Every request made.
	 *
	 * @return array<int, array{method: string, url: string, args: array}>
	 */
	public static function requests(): array {
		return self::$requests;
	}

	/**
	 * How many requests were made.
	 *
	 * @return int
	 */
	public static function count(): int {
		return count( self::$requests );
	}

	/**
	 * The last request.
	 *
	 * @return array{method: string, url: string, args: array}|null
	 */
	public static function last(): ?array {
		return self::$requests[ count( self::$requests ) - 1 ] ?? null;
	}

	/**
	 * Forget it all.
	 *
	 * @return void
	 */
	public static function reset(): void {
		self::$queue    = array();
		self::$requests = array();
	}
}
