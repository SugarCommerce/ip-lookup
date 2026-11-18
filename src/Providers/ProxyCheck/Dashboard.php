<?php
/**
 * ProxyCheck dashboard
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Providers\ProxyCheck;

use SugarCommerce\IpLookup\Providers\ProxyCheck\Response\Dashboard\DetectionEntry;
use SugarCommerce\IpLookup\Providers\ProxyCheck\Response\Dashboard\ListEntries;
use SugarCommerce\IpLookup\Providers\ProxyCheck\Response\Dashboard\QueryStatistics;
use SugarCommerce\IpLookup\Providers\ProxyCheck\Response\Dashboard\TagEntry;
use SugarCommerce\IpLookup\Providers\ProxyCheck\Response\Dashboard\UsageStatistics;
use WP_Error;

/**
 * Trait Dashboard
 *
 * ProxyCheck's dashboard API: what the account has caught, how much of its
 * allowance is left, and its own block, allow and CORS lists. Needs a key,
 * with Dashboard API Access switched on in the account.
 *
 * Exports are cached like any other answer; pass `$force_check` to ask
 * again. The lists are never cached.
 *
 * @since 1.0.0
 */
trait Dashboard {

	/**
	 * Recent detections.
	 *
	 * @since 1.0.0
	 *
	 * @param int  $limit       How many.
	 * @param int  $offset      From where.
	 * @param bool $force_check Skip the cache.
	 *
	 * @return DetectionEntry|WP_Error
	 */
	public function export_detections( int $limit = 100, int $offset = 0, bool $force_check = false ): DetectionEntry|WP_Error {
		$data = $this->dashboard_export(
			"detections|{$limit}|{$offset}",
			'export/detections/',
			array(
				'json'   => 1,
				'limit'  => $limit,
				'offset' => $offset,
			),
			$force_check
		);

		return is_wp_error( $data ) ? $data : new DetectionEntry( $data );
	}

	/**
	 * Recent detections, formatted for a table. Empty on failure.
	 *
	 * @since 1.0.0
	 *
	 * @param int  $limit       How many.
	 * @param int  $offset      From where.
	 * @param bool $force_check Skip the cache.
	 *
	 * @return array
	 */
	public function get_formatted_detections( int $limit = 100, int $offset = 0, bool $force_check = false ): array {
		$detections = $this->export_detections( $limit, $offset, $force_check );

		return is_wp_error( $detections ) ? array() : $detections->format();
	}

	/**
	 * Tagged queries.
	 *
	 * @since 1.0.0
	 *
	 * @param array $options     `limit` (100), `offset` (0), `addresses`
	 *                           (false), and `days`, or `start` and `end`.
	 * @param bool  $force_check Skip the cache.
	 *
	 * @return TagEntry|WP_Error
	 */
	public function export_tags( array $options = array(), bool $force_check = false ): TagEntry|WP_Error {
		$params = array_filter(
			array_merge(
				array(
					'limit'     => 100,
					'offset'    => 0,
					'addresses' => false,
					'days'      => null,
					'start'     => null,
					'end'       => null,
				),
				$options
			),
			fn ( $value ) => null !== $value
		);

		$params['addresses'] = (int) $params['addresses'];

		$data = $this->dashboard_export( 'tags|' . md5( serialize( $params ) ), 'export/tags/', $params, $force_check );

		return is_wp_error( $data ) ? $data : new TagEntry( $data );
	}

	/**
	 * Tagged queries, formatted. Empty on failure.
	 *
	 * @since 1.0.0
	 *
	 * @param array $options     As export_tags().
	 * @param bool  $force_check Skip the cache.
	 *
	 * @return array
	 */
	public function get_formatted_tags( array $options = array(), bool $force_check = false ): array {
		$tags = $this->export_tags( $options, $force_check );

		return is_wp_error( $tags ) ? array() : $tags->format();
	}

	/**
	 * Thirty days of query statistics.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $force_check Skip the cache.
	 *
	 * @return QueryStatistics|WP_Error
	 */
	public function export_queries( bool $force_check = false ): QueryStatistics|WP_Error {
		$data = $this->dashboard_export( 'queries_30day', 'export/queries/', array( 'json' => 1 ), $force_check );

		return is_wp_error( $data ) ? $data : new QueryStatistics( $data );
	}

	/**
	 * Query statistics by day, with totals. Zeros on failure.
	 *
	 * @since 1.0.0
	 *
	 * @param int  $days        How many days.
	 * @param bool $force_check Skip the cache.
	 *
	 * @return array
	 */
	public function get_formatted_queries( int $days = 30, bool $force_check = false ): array {
		$queries = $this->export_queries( $force_check );

		if ( ! is_wp_error( $queries ) ) {
			return $queries->format( $days );
		}

		return array(
			'period' => $days,
			'days'   => array(),
			'totals' => array_fill_keys( array( 'proxies', 'vpns', 'undetected', 'disposable_emails', 'reusable_emails', 'refused_queries', 'custom_rules', 'blacklisted', 'total_queries' ), 0 ),
			'today'  => null,
		);
	}

	/**
	 * The account's allowance and how much of it is used.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $force_check Skip the cache.
	 *
	 * @return UsageStatistics|WP_Error
	 */
	public function get_usage( bool $force_check = false ): UsageStatistics|WP_Error {
		$data = $this->dashboard_export( 'usage', 'export/usage/', array(), $force_check );

		return is_wp_error( $data ) ? $data : new UsageStatistics( $data );
	}

	/**
	 * The usage, formatted. Zeros on failure.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $force_check Skip the cache.
	 *
	 * @return array
	 */
	public function get_formatted_usage( bool $force_check = false ): array {
		$usage = $this->get_usage( $force_check );

		if ( ! is_wp_error( $usage ) ) {
			return $usage->format();
		}

		return array(
			'used'            => 0,
			'limit'           => 0,
			'total'           => 0,
			'plan'            => 'Unknown',
			'burst_available' => 0,
			'burst_limit'     => 0,
			'percentage'      => 0.0,
			'remaining'       => 0,
		);
	}

	/**
	 * Queries used today. 0 on failure.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $force_check Skip the cache.
	 *
	 * @return int
	 */
	public function get_used_tokens( bool $force_check = false ): int {
		$usage = $this->get_usage( $force_check );

		return is_wp_error( $usage ) ? 0 : $usage->get_used_tokens();
	}

	/**
	 * The daily allowance. 0 on failure.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $force_check Skip the cache.
	 *
	 * @return int
	 */
	public function get_token_limit( bool $force_check = false ): int {
		$usage = $this->get_usage( $force_check );

		return is_wp_error( $usage ) ? 0 : $usage->get_token_limit();
	}

	/**
	 * How much of the allowance is used, as a percentage.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $force_check Skip the cache.
	 *
	 * @return float
	 */
	public function get_usage_percentage( bool $force_check = false ): float {
		$limit = $this->get_token_limit( $force_check );

		return $limit > 0 ? round( ( $this->get_used_tokens() / $limit ) * 100, 2 ) : 0.0;
	}

	/**
	 * Queries left today. 0 on failure.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $force_check Skip the cache.
	 *
	 * @return int
	 */
	public function get_remaining_tokens( bool $force_check = false ): int {
		$usage = $this->get_usage( $force_check );

		return is_wp_error( $usage ) ? 0 : $usage->get_remaining_tokens();
	}

	/**
	 * Burst tokens available. 0 on failure.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $force_check Skip the cache.
	 *
	 * @return int
	 */
	public function get_burst_tokens( bool $force_check = false ): int {
		$usage = $this->get_usage( $force_check );

		return is_wp_error( $usage ) ? 0 : $usage->get_burst_tokens();
	}

	/**
	 * Burst tokens allowed. 0 on failure.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $force_check Skip the cache.
	 *
	 * @return int
	 */
	public function get_burst_token_limit( bool $force_check = false ): int {
		$usage = $this->get_usage( $force_check );

		return is_wp_error( $usage ) ? 0 : $usage->get_burst_token_limit();
	}

	/**
	 * Whether today's allowance is spent -- or unknown, which is treated the
	 * same.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $force_check Skip the cache.
	 *
	 * @return bool
	 */
	public function is_token_limit_exceeded( bool $force_check = false ): bool {
		return $this->get_remaining_tokens( $force_check ) <= 0;
	}

	/**
	 * "1,000 / 2,000 available", for a settings screen. Escaped.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function get_formatted_burst_usage(): string {
		return sprintf(
			/* translators: 1: burst tokens available, 2: burst tokens allowed. */
			esc_html__( '%1$s / %2$s available', 'sugarcommerce' ),
			number_format_i18n( $this->get_burst_tokens() ),
			number_format_i18n( $this->get_burst_token_limit() )
		);
	}

	/**
	 * "500 / 1,000 queries (50.0% used)", for a settings screen. Escaped.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function get_formatted_token_usage(): string {
		return sprintf(
			/* translators: 1: queries used, 2: queries allowed, 3: the percentage used. */
			esc_html__( '%1$s / %2$s queries (%3$s%% used)', 'sugarcommerce' ),
			number_format_i18n( $this->get_used_tokens() ),
			number_format_i18n( $this->get_token_limit() ),
			number_format_i18n( $this->get_usage_percentage(), 1 )
		);
	}

	/**
	 * The account's blacklist.
	 *
	 * @since 1.0.0
	 *
	 * @return ListEntries|WP_Error
	 */
	public function get_blacklist(): ListEntries|WP_Error {
		return $this->manage_list( 'print', 'blacklist' );
	}

	/**
	 * Replace the blacklist.
	 *
	 * @since 1.0.0
	 *
	 * @param string|string[] $ips Addresses, as a list or one per line.
	 *
	 * @return ListEntries|WP_Error
	 */
	public function set_blacklist( string|array $ips ): ListEntries|WP_Error {
		return $this->manage_list( 'set', 'blacklist', self::format_list( $ips ) );
	}

	/**
	 * Add to the blacklist.
	 *
	 * @since 1.0.0
	 *
	 * @param string|string[] $ips Addresses.
	 *
	 * @return ListEntries|WP_Error
	 */
	public function add_to_blacklist( string|array $ips ): ListEntries|WP_Error {
		return $this->manage_list( 'add', 'blacklist', self::format_list( $ips ) );
	}

	/**
	 * Remove from the blacklist.
	 *
	 * @since 1.0.0
	 *
	 * @param string|string[] $ips Addresses.
	 *
	 * @return ListEntries|WP_Error
	 */
	public function remove_from_blacklist( string|array $ips ): ListEntries|WP_Error {
		return $this->manage_list( 'remove', 'blacklist', self::format_list( $ips ) );
	}

	/**
	 * Empty the blacklist.
	 *
	 * @since 1.0.0
	 *
	 * @return ListEntries|WP_Error
	 */
	public function clear_blacklist(): ListEntries|WP_Error {
		return $this->manage_list( 'clear', 'blacklist' );
	}

	/**
	 * The account's whitelist.
	 *
	 * @since 1.0.0
	 *
	 * @return ListEntries|WP_Error
	 */
	public function get_whitelist(): ListEntries|WP_Error {
		return $this->manage_list( 'print', 'whitelist' );
	}

	/**
	 * Replace the whitelist.
	 *
	 * @since 1.0.0
	 *
	 * @param string|string[] $ips Addresses.
	 *
	 * @return ListEntries|WP_Error
	 */
	public function set_whitelist( string|array $ips ): ListEntries|WP_Error {
		return $this->manage_list( 'set', 'whitelist', self::format_list( $ips ) );
	}

	/**
	 * Add to the whitelist.
	 *
	 * @since 1.0.0
	 *
	 * @param string|string[] $ips Addresses.
	 *
	 * @return ListEntries|WP_Error
	 */
	public function add_to_whitelist( string|array $ips ): ListEntries|WP_Error {
		return $this->manage_list( 'add', 'whitelist', self::format_list( $ips ) );
	}

	/**
	 * Remove from the whitelist.
	 *
	 * @since 1.0.0
	 *
	 * @param string|string[] $ips Addresses.
	 *
	 * @return ListEntries|WP_Error
	 */
	public function remove_from_whitelist( string|array $ips ): ListEntries|WP_Error {
		return $this->manage_list( 'remove', 'whitelist', self::format_list( $ips ) );
	}

	/**
	 * Empty the whitelist.
	 *
	 * @since 1.0.0
	 *
	 * @return ListEntries|WP_Error
	 */
	public function clear_whitelist(): ListEntries|WP_Error {
		return $this->manage_list( 'clear', 'whitelist' );
	}

	/**
	 * The origins allowed to call ProxyCheck from a browser with this key.
	 *
	 * @since 1.0.0
	 *
	 * @return ListEntries|WP_Error
	 */
	public function get_cors_origins(): ListEntries|WP_Error {
		return $this->manage_list( 'print', 'cors' );
	}

	/**
	 * Replace the CORS origins.
	 *
	 * @since 1.0.0
	 *
	 * @param string|string[] $origins Origins.
	 *
	 * @return ListEntries|WP_Error
	 */
	public function set_cors_origins( string|array $origins ): ListEntries|WP_Error {
		return $this->manage_list( 'set', 'cors', self::format_list( $origins ) );
	}

	/**
	 * Add CORS origins.
	 *
	 * @since 1.0.0
	 *
	 * @param string|string[] $origins Origins.
	 *
	 * @return ListEntries|WP_Error
	 */
	public function add_cors_origins( string|array $origins ): ListEntries|WP_Error {
		return $this->manage_list( 'add', 'cors', self::format_list( $origins ) );
	}

	/**
	 * Remove CORS origins.
	 *
	 * @since 1.0.0
	 *
	 * @param string|string[] $origins Origins.
	 *
	 * @return ListEntries|WP_Error
	 */
	public function remove_cors_origins( string|array $origins ): ListEntries|WP_Error {
		return $this->manage_list( 'remove', 'cors', self::format_list( $origins ) );
	}

	/**
	 * Remove every CORS origin.
	 *
	 * @since 1.0.0
	 *
	 * @return ListEntries|WP_Error
	 */
	public function clear_cors_origins(): ListEntries|WP_Error {
		return $this->manage_list( 'clear', 'cors' );
	}

	/**
	 * Read, change or empty one of the account's lists.
	 *
	 * @since 1.0.0
	 *
	 * @param string      $action    `print` (or `list`), `add`, `remove`, `set`, `clear`, `erase` or `forcedl`.
	 * @param string      $list_name `blacklist`, `whitelist`, `cors`, or a custom list's name.
	 * @param string|null $data      One entry per line, for add, remove and set.
	 *
	 * @return ListEntries|WP_Error
	 */
	public function manage_list( string $action, string $list_name, ?string $data = null ): ListEntries|WP_Error {
		$action = 'list' === $action ? 'print' : $action;

		if ( ! in_array( $action, array( 'print', 'add', 'remove', 'set', 'clear', 'erase', 'forcedl' ), true ) ) {
			/* translators: %s: the action asked for. */
			return $this->error( 'invalid_action', sprintf( __( 'Not a list action: %s', 'sugarcommerce' ), $action ) );
		}

		if ( 1 !== preg_match( '/^[A-Za-z0-9_-]+$/', $list_name ) ) {
			return $this->error( 'invalid_list', __( 'Not a list name.', 'sugarcommerce' ) );
		}

		$args = array();

		if ( null !== $data && in_array( $action, array( 'add', 'remove', 'set' ), true ) ) {
			$args = array( 'body' => array( 'data' => $data ) );
		}

		$endpoint = $list_name . '/' . ( 'print' === $action ? 'list' : $action ) . '/';
		$answer   = $this->dashboard_request( $endpoint, array( 'json' => 1 ), $args );

		return is_wp_error( $answer ) ? $answer : new ListEntries( $answer );
	}

	/**
	 * A list as ProxyCheck takes it: one entry per line.
	 *
	 * @param string|string[] $items The entries.
	 *
	 * @return string
	 */
	private static function format_list( string|array $items ): string {
		if ( is_array( $items ) ) {
			return implode( "\n", array_filter( array_map( 'trim', array_map( 'strval', $items ) ) ) );
		}

		return trim( $items );
	}

	/**
	 * An export, through the cache unless forced.
	 *
	 * @param string $identifier  What is asked.
	 * @param string $endpoint    The endpoint.
	 * @param array  $params      Its parameters.
	 * @param bool   $force_check Skip the cache.
	 *
	 * @return array|WP_Error
	 */
	private function dashboard_export( string $identifier, string $endpoint, array $params, bool $force_check ): array|WP_Error {
		$identifier = 'dashboard|' . $identifier;

		if ( $force_check ) {
			$this->clear_cache( $identifier );
		}

		return $this->remember( $identifier, fn () => $this->dashboard_request( $endpoint, $params ) );
	}

	/**
	 * Call the dashboard API.
	 *
	 * @param string $endpoint The endpoint.
	 * @param array  $params   Query parameters.
	 * @param array  $args     Request arguments; a body makes it a POST.
	 *
	 * @return array|WP_Error
	 */
	private function dashboard_request( string $endpoint, array $params = array(), array $args = array() ): array|WP_Error {
		if ( '' === $this->api_key ) {
			return $this->error( 'missing_key', __( 'The ProxyCheck dashboard API needs a key.', 'sugarcommerce' ) );
		}

		$url  = 'https://proxycheck.io/dashboard/' . ltrim( $endpoint, '/' ) . '?' . http_build_query( $params + array( 'key' => $this->api_key ) );
		$data = $this->json( $this->request( isset( $args['body'] ) ? 'POST' : 'GET', $url, $args ) );

		if ( is_wp_error( $data ) ) {
			return $data;
		}

		if ( in_array( $data['status'] ?? '', array( 'denied', 'error' ), true ) ) {
			return $this->error( 'api_access_denied', (string) ( $data['message'] ?? __( 'ProxyCheck refused: switch on Dashboard API Access in the proxycheck.io dashboard.', 'sugarcommerce' ) ) );
		}

		return $data;
	}
}
