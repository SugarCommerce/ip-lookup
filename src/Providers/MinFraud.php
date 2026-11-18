<?php
/**
 * MaxMind minFraud
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Providers;

use SugarCommerce\IpLookup\Providers\MinFraud\Score;
use SugarCommerce\IpLookup\Result;
use SugarCommerce\IpLookup\Service;
use WP_Error;

/**
 * Class MinFraud
 *
 * MaxMind minFraud Score (https://dev.maxmind.com/minfraud): a risk for a
 * whole transaction -- the device, the email, the billing and shipping
 * addresses, the card. The more of the payload is filled in, the better the
 * score; an address on its own is a weak signal.
 *
 * It scores, it does not decide. Where the threshold sits is a business
 * question, worth reviewing against your own chargebacks.
 *
 * @since 1.0.0
 */
class MinFraud extends Service {

	protected const ID = 'minfraud';

	protected const NAME = 'minFraud';

	protected const CACHE_TTL = 600;

	/**
	 * The Score endpoint.
	 */
	private const SCORE_ENDPOINT = 'https://minfraud.maxmind.com/minfraud/v2.0/score';

	/**
	 * Build the client.
	 *
	 * @since 1.0.0
	 *
	 * @param string $account_id  The MaxMind account id.
	 * @param string $license_key The licence key.
	 * @param array  $args        The settings every provider takes:
	 *                            `cache`, `cache_ttl`, `failure_ttl`.
	 */
	public function __construct( private string $account_id = '', #[\SensitiveParameter] string $license_key = '', array $args = array() ) {
		parent::__construct( $license_key, $args );
	}

	/**
	 * The account id.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function get_account_id(): string {
		return $this->account_id;
	}

	/**
	 * Score a transaction.
	 *
	 * @since 1.0.0
	 *
	 * @param array $payload minFraud's request body: `device`, `email`,
	 *                       `billing`, `shipping`, `payment`, `order`...
	 *
	 * @return Score|WP_Error
	 */
	public function check_score( array $payload ): Score|WP_Error {
		if ( '' === $this->account_id || '' === $this->api_key ) {
			return $this->error( 'missing_credentials', __( 'minFraud needs an account id and a licence key.', 'sugarcommerce' ) );
		}

		$data = $this->remember( (string) wp_json_encode( self::sorted( $payload ) ), fn () => $this->fetch( $payload ) );

		return is_wp_error( $data ) ? $data : new Score( $data );
	}

	/**
	 * Score an address on its own, answered the common way.
	 *
	 * @since 1.0.0
	 *
	 * @param string $ip The address.
	 *
	 * @return Result|WP_Error
	 */
	public function lookup( string $ip ): Result|WP_Error {
		$ip = trim( $ip );

		if ( ! self::is_lookupable( $ip ) ) {
			return $this->invalid_ip( $ip );
		}

		$score = $this->check_score( array( 'device' => array( 'ip_address' => $ip ) ) );

		if ( is_wp_error( $score ) ) {
			return $score;
		}

		return new Result( self::ID, $ip, array( 'risk_score' => $score->get_ip_risk() ?? $score->get_risk_score() ), $score );
	}

	/**
	 * Ask the API.
	 *
	 * @param array $payload The request body.
	 *
	 * @return array|WP_Error
	 */
	private function fetch( array $payload ): array|WP_Error {
		$response = $this->request(
			'POST',
			self::SCORE_ENDPOINT,
			array(
				'headers' => array(
					'Content-Type'  => 'application/json',
					'Authorization' => 'Basic ' . base64_encode( $this->account_id . ':' . $this->api_key ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- HTTP basic authentication.
				),
				'body'    => (string) wp_json_encode( $payload ),
				'timeout' => 10,
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		if ( ! is_array( $response['data'] ) ) {
			return $this->error(
				'bad_response',
				__( 'minFraud returned a response that could not be read.', 'sugarcommerce' ),
				array(
					'status' => $response['status'],
					'body'   => $response['body'],
				)
			);
		}

		// An error has `code` and `error` in place of a score: never read it
		// as a score of 0.
		if ( $response['status'] >= 400 || isset( $response['data']['code'] ) ) {
			return $this->error(
				'api_error',
				(string) ( $response['data']['error'] ?? __( 'minFraud API error.', 'sugarcommerce' ) ),
				array(
					'status' => $response['status'],
					'code'   => (string) ( $response['data']['code'] ?? '' ),
				)
			);
		}

		return $response['data'];
	}

	/**
	 * A payload with its keys sorted at every level, so the same request
	 * written in another order shares its cache entry.
	 *
	 * @param array $payload The payload.
	 *
	 * @return array
	 */
	private static function sorted( array $payload ): array {
		ksort( $payload );

		foreach ( $payload as $key => $value ) {
			if ( is_array( $value ) ) {
				$payload[ $key ] = self::sorted( $value );
			}
		}

		return $payload;
	}
}
