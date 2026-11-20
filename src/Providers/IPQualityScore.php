<?php
/**
 * IPQualityScore
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Providers;

use SugarCommerce\IpLookup\Providers\IPQualityScore\Response\Email;
use SugarCommerce\IpLookup\Providers\IPQualityScore\Response\IP;
use SugarCommerce\IpLookup\Result;
use SugarCommerce\IpLookup\Provider;
use SugarCommerce\IpLookup\Support\Address;
use SugarCommerce\Network\Request;
use SugarCommerce\Network\Remote\Service;
use WP_Error;

/**
 * Class IPQualityScore
 *
 * IPQualityScore (https://www.ipqualityscore.com/documentation): the two
 * questions a checkout keeps asking, behind one key -- is this address a
 * proxy, and is this inbox real. Its phone, URL, malware, leak, transaction,
 * reporting, list and credit endpoints are not wrapped: nothing used them.
 *
 * Its strictness is a dial, 0 to 3: each step catches more fraud and more
 * innocent customers with it.
 *
 * @since 1.0.0
 */
class IPQualityScore extends Service implements Provider {

	protected const string ID = 'ipqualityscore';

	protected const string NAME = 'IPQualityScore';

	protected const string CACHE_GROUP = 'iplookup';

	/**
	 * The API.
	 */
	private const string API_BASE = 'https://ipqualityscore.com/api/json/';

	/**
	 * How each endpoint is called. Every other endpoint is a POST to
	 * `{base}{endpoint}/{key}`.
	 *
	 * `value` is the parameter that goes into the path after the key.
	 */
	private const array ENDPOINTS = array(
		'ip' => array(
			'method' => 'GET',
			'value'  => 'ip',
		),
	);

	/**
	 * How suspicious to be, 0 to 3.
	 *
	 * @var int
	 */
	private int $strictness = 0;

	/**
	 * Whether a public hotspot or a corporate gateway is let off.
	 *
	 * @var bool
	 */
	private bool $allow_public_access_points = false;

	/**
	 * Whether to score lightly, for fewer false positives.
	 *
	 * @var bool
	 */
	private bool $lighter_penalties = false;

	/**
	 * Build the client.
	 *
	 * @since 1.0.0
	 *
	 * @param string $api_key The key.
	 * @param array  $args    The settings every provider takes (`cache`,
	 *                        `cache_ttl`, `failure_ttl`), and `strictness`,
	 *                        `allow_public_access_points` and
	 *                        `lighter_penalties`.
	 */
	public function __construct( #[\SensitiveParameter] string $api_key = '', array $args = array() ) {
		parent::__construct( $api_key, $args );

		if ( isset( $args['strictness'] ) ) {
			$this->set_strictness( (int) $args['strictness'] );
		}

		if ( isset( $args['allow_public_access_points'] ) ) {
			$this->set_allow_public_access_points( (bool) $args['allow_public_access_points'] );
		}

		if ( isset( $args['lighter_penalties'] ) ) {
			$this->set_lighter_penalties( (bool) $args['lighter_penalties'] );
		}
	}

	/**
	 * How suspicious to be.
	 *
	 * @since 1.0.0
	 *
	 * @param int $strictness 0 to 3.
	 *
	 * @return static
	 */
	public function set_strictness( int $strictness ): static {
		$this->strictness = max( 0, min( 3, $strictness ) );

		return $this;
	}

	/**
	 * How suspicious it is, 0 to 3.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	public function get_strictness(): int {
		return $this->strictness;
	}

	/**
	 * Let off public hotspots and corporate gateways.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $allow Whether to.
	 *
	 * @return static
	 */
	public function set_allow_public_access_points( bool $allow ): static {
		$this->allow_public_access_points = $allow;

		return $this;
	}

	/**
	 * Score lightly, for fewer false positives.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $lighter Whether to.
	 *
	 * @return static
	 */
	public function set_lighter_penalties( bool $lighter ): static {
		$this->lighter_penalties = $lighter;

		return $this;
	}

	/**
	 * What IPQualityScore knows about an address.
	 *
	 * @since 1.0.0
	 *
	 * @param string $ip     The address.
	 * @param array  $params More of the API's parameters.
	 *
	 * @return IP|WP_Error
	 */
	public function check_ip( string $ip, array $params = array() ): IP|WP_Error {
		$address = Address::canonical( $ip );

		if ( null === $address ) {
			return $this->invalid_ip( trim( $ip ) );
		}

		$ip = $address;

		return $this->cached( IP::class, 'ip_' . $ip, 'ip', array( 'ip' => $ip ) + $params );
	}

	/**
	 * Whether an email address is real, deliverable and safe.
	 *
	 * @since 1.0.0
	 *
	 * @param string $email  The address.
	 * @param array  $params More of the API's parameters.
	 *
	 * @return Email|WP_Error
	 */
	public function validate_email( string $email, array $params = array() ): Email|WP_Error {
		if ( ! filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
			/* translators: %s: the email address. */
			return $this->error( 'invalid_email', sprintf( __( 'Not an email address: %s', 'sugarcommerce' ), $email ) );
		}

		return $this->cached( Email::class, 'email_' . $email, 'email', array( 'email' => $email ) + $params );
	}

	/**
	 * Ask about an address, answered the common way.
	 *
	 * @since 1.0.0
	 *
	 * @param string $ip The address.
	 *
	 * @return Result|WP_Error
	 */
	#[\Override]
	public function lookup( string $ip ): Result|WP_Error {
		$check = $this->check_ip( $ip );

		if ( is_wp_error( $check ) ) {
			return $check;
		}

		$connection = $check->get_connection_type();

		return new Result(
			self::ID,
			Address::canonical( $ip ) ?? trim( $ip ),
			array(
				'risk_score'      => $check->get_fraud_score(),
				'is_proxy'        => $check->is_proxy(),
				'is_vpn'          => $check->is_vpn(),
				'is_tor'          => $check->is_tor(),
				'is_bot'          => $check->is_bot(),
				'is_abusive'      => $check->has_recent_abuse(),
				'is_hosting'      => null === $connection ? null : 'datacenter' === strtolower( str_replace( ' ', '', $connection ) ),
				'country_code'    => $check->get_country_code(),
				'region'          => $check->get_region(),
				'city'            => $check->get_city(),
				'postal_code'     => $check->get_zip_code(),
				'latitude'        => $check->get_latitude(),
				'longitude'       => $check->get_longitude(),
				'timezone'        => $check->get_timezone(),
				'asn'             => $check->get_asn(),
				'isp'             => $check->get_isp(),
				'organisation'    => $check->get_organization(),
				'connection_type' => $connection,
			),
			$check
		);
	}

	/**
	 * Ask an endpoint, through the cache, and wrap the answer.
	 *
	 * @param class-string $response   The response class.
	 * @param string       $identifier What is asked.
	 * @param string       $endpoint   The endpoint.
	 * @param array        $params     Its parameters.
	 *
	 * @return object|WP_Error
	 */
	private function cached( string $response, string $identifier, string $endpoint, array $params ): object {
		$data = $this->remember( $identifier . '|' . md5( serialize( $params ) ), fn () => $this->call( $endpoint, $params ) );

		return is_wp_error( $data ) ? $data : new $response( $data );
	}

	/**
	 * Call an endpoint.
	 *
	 * @param string $endpoint The endpoint.
	 * @param array  $params   Its parameters.
	 *
	 * @return array|WP_Error The decoded answer.
	 */
	private function call( string $endpoint, array $params = array() ): array|WP_Error {
		$config = self::ENDPOINTS[ $endpoint ] ?? array( 'method' => 'POST' );
		$params = array_merge(
			array(
				'strictness'                 => $this->strictness,
				'user_agent'                 => Request::agent(),
				'user_language'              => self::header( 'HTTP_ACCEPT_LANGUAGE' ),
				'allow_public_access_points' => $this->allow_public_access_points,
				'lighter_penalties'          => $this->lighter_penalties,
				'fast'                       => false,
			),
			$params
		);

		$url = self::API_BASE . $endpoint . '/' . rawurlencode( $this->api_key );

		if ( isset( $config['value'] ) ) {
			$url .= '/' . (string) ( $params[ $config['value'] ] ?? '' );
			unset( $params[ $config['value'] ] );
		}

		$args = array();

		if ( 'GET' === $config['method'] ) {
			$url .= empty( $params ) ? '' : '?' . http_build_query( $params );
		} else {
			$args['body'] = $params;
		}

		return $this->answer( $this->request( $config['method'], $url, $args ) );
	}

	/**
	 * Read an answer: IPQualityScore says 200 even when it refuses, and puts
	 * the refusal in `success` and `message`.
	 *
	 * @param array|WP_Error $response What request() returned.
	 *
	 * @return array|WP_Error
	 */
	private function answer( array|WP_Error $response ): array|WP_Error {
		$data = $this->json( $response );

		if ( is_wp_error( $data ) ) {
			return $data;
		}

		if ( isset( $data['errors'] ) && array() !== $data['errors'] ) {
			return $this->error( 'api_error', is_array( $data['errors'] ) ? implode( ' ', array_map( 'strval', $data['errors'] ) ) : (string) $data['errors'] );
		}

		if ( false === ( $data['success'] ?? null ) ) {
			return $this->error( 'api_error', (string) ( $data['message'] ?? __( 'IPQualityScore refused the request.', 'sugarcommerce' ) ) );
		}

		return $data;
	}

	/**
	 * A request header to pass on, unslashed and cleaned.
	 *
	 * @param string $key The `$_SERVER` key.
	 *
	 * @return string
	 */
	private static function header( string $key ): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- unslashed and cleaned on the next line.
		$value = $_SERVER[ $key ] ?? '';

		return is_string( $value ) ? sanitize_text_field( wp_unslash( $value ) ) : '';
	}
}
