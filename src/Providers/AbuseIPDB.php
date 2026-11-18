<?php
/**
 * AbuseIPDB
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Providers;

use SugarCommerce\IpLookup\Providers\AbuseIPDB\Check;
use SugarCommerce\IpLookup\Result;
use SugarCommerce\IpLookup\Service;
use WP_Error;

/**
 * Class AbuseIPDB
 *
 * AbuseIPDB's Check API (https://docs.abuseipdb.com/): reports collected
 * from thousands of sites, turned into a confidence score out of 100. The
 * free tier allows about a thousand checks a day.
 *
 * A score is a reputation, not a verdict: the address may be a shared NAT
 * or a mobile carrier. Treat a high one as a reason to look closer.
 *
 * @since 1.0.0
 */
class AbuseIPDB extends Service {

	protected const ID = 'abuseipdb';

	protected const NAME = 'AbuseIPDB';

	/**
	 * The Check endpoint.
	 */
	private const CHECK_ENDPOINT = 'https://api.abuseipdb.com/api/v2/check';

	/**
	 * AbuseIPDB's own line for "high confidence of abuse".
	 */
	public const ABUSIVE_SCORE = 75;

	/**
	 * How many days of reports the score is worked out over, 1 to 365.
	 *
	 * @var int
	 */
	private int $max_age_days = 90;

	/**
	 * Build the client.
	 *
	 * @since 1.0.0
	 *
	 * @param string $api_key The key, from the AbuseIPDB account page.
	 * @param array  $args    The settings every provider takes (`cache`,
	 *                        `cache_ttl`, `failure_ttl`), and
	 *                        `max_age_days` -- days of reports to count,
	 *                        default 90.
	 */
	public function __construct( #[\SensitiveParameter] string $api_key = '', array $args = array() ) {
		parent::__construct( $api_key, $args );

		if ( isset( $args['max_age_days'] ) ) {
			$this->set_max_age_days( (int) $args['max_age_days'] );
		}
	}

	/**
	 * How many days of reports to count.
	 *
	 * @since 1.0.0
	 *
	 * @param int $days 1 to 365.
	 *
	 * @return static
	 */
	public function set_max_age_days( int $days ): static {
		$this->max_age_days = max( 1, min( 365, $days ) );

		return $this;
	}

	/**
	 * How many days of reports are counted.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	public function get_max_age_days(): int {
		return $this->max_age_days;
	}

	/**
	 * Check an address.
	 *
	 * @since 1.0.0
	 *
	 * @param string $ip The address.
	 *
	 * @return Check|WP_Error
	 */
	public function check_ip( string $ip ): Check|WP_Error {
		$ip = trim( $ip );

		if ( '' === $this->api_key ) {
			return $this->error( 'missing_key', __( 'AbuseIPDB needs an API key.', 'sugarcommerce' ) );
		}

		if ( ! self::is_lookupable( $ip ) ) {
			return $this->invalid_ip( $ip );
		}

		// The score is worked out over the window, so two windows ask two
		// different questions and must not share an answer.
		$data = $this->remember( $ip . '|' . $this->max_age_days, fn () => $this->fetch( $ip ) );

		return is_wp_error( $data ) ? $data : new Check( $data );
	}

	/**
	 * Check an address, answered the common way.
	 *
	 * @since 1.0.0
	 *
	 * @param string $ip The address.
	 *
	 * @return Result|WP_Error
	 */
	public function lookup( string $ip ): Result|WP_Error {
		$check = $this->check_ip( $ip );

		if ( is_wp_error( $check ) ) {
			return $check;
		}

		return new Result(
			self::ID,
			trim( $ip ),
			array(
				'risk_score'      => $check->get_confidence_score(),
				'is_abusive'      => $check->is_abusive( self::ABUSIVE_SCORE ),
				'is_tor'          => $check->is_tor(),
				'is_hosting'      => '' === $check->get_usage_type() ? null : str_contains( $check->get_usage_type(), 'Data Center' ),
				'country_code'    => $check->get_country_code(),
				'isp'             => $check->get( 'isp' ),
				'connection_type' => $check->get_usage_type(),
			),
			$check
		);
	}

	/**
	 * Ask the API.
	 *
	 * @param string $ip The address.
	 *
	 * @return array|WP_Error The `data` block.
	 */
	private function fetch( string $ip ): array|WP_Error {
		$url = add_query_arg(
			array(
				'ipAddress'    => $ip,
				'maxAgeInDays' => $this->max_age_days,
				'verbose'      => '',
			),
			self::CHECK_ENDPOINT
		);

		$response = $this->request(
			'GET',
			$url,
			array(
				'headers' => array( 'Key' => $this->api_key ),
				'timeout' => 10,
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		if ( ! is_array( $response['data'] ) ) {
			return $this->error(
				'bad_response',
				__( 'AbuseIPDB returned a response that could not be read.', 'sugarcommerce' ),
				array(
					'status' => $response['status'],
					'body'   => $response['body'],
				)
			);
		}

		// An error comes back as an `errors` list in place of `data`.
		if ( $response['status'] >= 400 || isset( $response['data']['errors'] ) ) {
			$first = (array) ( $response['data']['errors'][0] ?? array() );

			return $this->error(
				'api_error',
				(string) ( $first['detail'] ?? __( 'AbuseIPDB API error.', 'sugarcommerce' ) ),
				array( 'status' => $response['status'] )
			);
		}

		return (array) ( $response['data']['data'] ?? array() );
	}
}
