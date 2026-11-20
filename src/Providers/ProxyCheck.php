<?php
/**
 * ProxyCheck
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Providers;

use SugarCommerce\IpLookup\Models\ProxyCheck\Response\DisposableEmail;
use SugarCommerce\IpLookup\Models\ProxyCheck\Response\IP;
use SugarCommerce\IpLookup\Models\Result;
use SugarCommerce\IpLookup\Provider;
use SugarCommerce\IpLookup\Support\Address;
use SugarCommerce\IpLookup\Support\Field;
use SugarCommerce\IpLookup\Traits\ProxyCheck\Countries;
use SugarCommerce\IpLookup\Traits\ProxyCheck\Flags;
use SugarCommerce\IpLookup\Traits\ProxyCheck\Verdict;
use SugarCommerce\Network\Remote\Service;
use WP_Error;

/**
 * Class ProxyCheck
 *
 * ProxyCheck.io (https://proxycheck.io/api/): whether an address is a proxy
 * or a VPN -- down to which VPN, and whether that VPN keeps logs or takes
 * crypto -- its risk, where it is, and whether an email address is
 * disposable. Works without a key, on the free allowance.
 *
 * Every answer gets a verdict on top: `block` is yes for a proxy or a VPN,
 * a risk over 70, or a blocked country, and no again for an allowed one.
 *
 * The query flags are in Flags, the country lists in Countries and the
 * verdict in Verdict; this class asks.
 *
 * @since 1.0.0
 */
class ProxyCheck extends Service implements Provider {

	use Flags;
	use Countries;
	use Verdict;

	protected const string ID = 'proxycheck';

	protected const string NAME = 'ProxyCheck';

	protected const string CACHE_GROUP = 'iplookup';

	protected const int CACHE_TTL = 600;

	/**
	 * The API.
	 */
	private const string API_BASE = 'https://proxycheck.io/v2/';

	/**
	 * Addresses per batch request without a key.
	 */
	public const int BATCH_MAX_SIZE = 100;

	/**
	 * Addresses per batch request with one.
	 */
	public const int BATCH_MAX_SIZE_REGISTERED = 1000;

	/**
	 * The risk above which an address is blocked.
	 */
	public const int BLOCK_RISK = 70;

	/**
	 * Check an address.
	 *
	 * @since 1.0.0
	 *
	 * @param string $ip      The address.
	 * @param array  $options Query flags for this check only.
	 *
	 * @return IP|WP_Error
	 */
	public function check_ip( string $ip, array $options = array() ): IP|WP_Error {
		$address = Address::canonical( $ip );

		if ( null === $address ) {
			return $this->invalid_ip( trim( $ip ) );
		}

		$ip = $address;

		$params = array_merge( $this->parameters, $options );

		// Kept as ProxyCheck said it; the verdict is worked out on the way
		// out, so changing the countries takes effect at once.
		$data = $this->remember( $ip . '|' . md5( serialize( $params ) ), fn () => $this->answer( $this->request( 'GET', $this->url( rawurlencode( $ip ), $params ) ) ) );

		return is_wp_error( $data ) ? $data : new IP( $this->add_block_status( $data, $ip ) );
	}

	/**
	 * Check many addresses at once.
	 *
	 * @since 1.0.0
	 *
	 * @param string[] $ips     The addresses.
	 * @param array    $options Query flags for these checks.
	 *
	 * @return array<string, IP>|WP_Error Keyed by address.
	 */
	public function check_ips( array $ips, array $options = array() ): array|WP_Error {
		$ips = Address::canonical_list( $ips );

		if ( empty( $ips ) ) {
			return $this->error( 'invalid_ips', __( 'No public IP addresses to check.', 'sugarcommerce' ) );
		}

		$params  = array_merge( $this->parameters, $options );
		$results = array();

		foreach ( array_chunk( $ips, '' === $this->api_key ? self::BATCH_MAX_SIZE : self::BATCH_MAX_SIZE_REGISTERED ) as $batch ) {
			$data = $this->answer( $this->request( 'POST', $this->url( '', $params ), array( 'body' => array( 'ips' => implode( ',', $batch ) ) ) ) );

			if ( is_wp_error( $data ) ) {
				return $data;
			}

			foreach ( $batch as $ip ) {
				if ( ! is_array( $data[ $ip ] ?? null ) ) {
					continue;
				}

				$results[ $ip ] = new IP(
					$this->add_block_status(
						array(
							'status'     => $data['status'] ?? 'ok',
							'node'       => $data['node'] ?? null,
							'query time' => $data['query time'] ?? null,
							$ip          => $data[ $ip ],
						),
						$ip
					)
				);
			}
		}

		return $results;
	}

	/**
	 * Whether an email address is from a disposable service.
	 *
	 * @since 1.0.0
	 *
	 * @param string $email The address.
	 * @param bool   $mask  Send only the domain: `anonymous@example.com`.
	 *
	 * @return DisposableEmail|WP_Error
	 */
	public function check_email( string $email, bool $mask = false ): DisposableEmail|WP_Error {
		if ( ! is_email( $email ) ) {
			/* translators: %s: the email address. */
			return $this->error( 'invalid_email', sprintf( __( 'Not an email address: %s', 'sugarcommerce' ), $email ) );
		}

		if ( $mask ) {
			$email = 'anonymous@' . substr( (string) strrchr( $email, '@' ), 1 );
		}

		$data = $this->remember( $email, fn () => $this->answer( $this->request( 'GET', $this->url( rawurlencode( $email ) ) ) ) );

		return is_wp_error( $data ) ? $data : new DisposableEmail( $this->add_block_status( $data, $email ) );
	}

	/**
	 * Check an address, answered the common way.
	 *
	 * Asks with the VPN operator, the network and the risk score on,
	 * whatever the client is set to.
	 *
	 * @since 1.0.0
	 *
	 * @param string $ip The address.
	 *
	 * @return Result|WP_Error
	 */
	#[\Override]
	public function lookup( string $ip ): Result|WP_Error {
		$check = $this->check_ip(
			$ip,
			array(
				'vpn'  => max( 1, $this->get_vpn() ),
				'asn'  => 1,
				'risk' => max( 1, $this->get_risk() ),
			)
		);

		if ( is_wp_error( $check ) ) {
			return $check;
		}

		$type        = strtoupper( (string) $check->get_type() );
		$country     = $check->get_country();
		$continent   = $check->get_continent();
		$coordinates = $check->get_coordinates();
		$network     = $check->get_network_type();

		return new Result(
			self::ID,
			Address::canonical( $ip ) ?? trim( $ip ),
			array(
				'risk_score'      => $check->get_risk_score(),
				'is_proxy'        => $check->is_proxy(),
				'is_vpn'          => $check->is_proxy() ? 'VPN' === $type : false,
				'is_tor'          => $check->is_proxy() ? 'TOR' === $type : false,
				'is_hosting'      => null === $network ? null : 'hosting' === strtolower( $network ),
				'country_code'    => $country['code'] ?? null,
				'is_eu'           => null === $country ? null : $country['is_eu'],
				'continent_code'  => $continent['code'] ?? null,
				'region'          => $check->get_region()['name'] ?? null,
				'city'            => $check->get_city(),
				'postal_code'     => $check->get_postcode(),
				'latitude'        => $coordinates['latitude'] ?? null,
				'longitude'       => $coordinates['longitude'] ?? null,
				'timezone'        => $check->get_timezone(),
				'asn'             => $check->get_asn(),
				'isp'             => $check->get_provider(),
				'organisation'    => $check->get_organisation(),
				'connection_type' => $network,
			),
			$check
		);
	}

	/**
	 * The URL for a check, with the key and the flags.
	 *
	 * @param string $path   What is checked.
	 * @param array  $params The flags.
	 *
	 * @return string
	 */
	private function url( string $path, array $params = array() ): string {
		if ( '' !== $this->api_key ) {
			$params['key'] = $this->api_key;
		}

		return self::API_BASE . $path . ( empty( $params ) ? '' : '?' . http_build_query( $params ) );
	}

	/**
	 * Read an answer: ProxyCheck says what went wrong in `status` and
	 * `message`.
	 *
	 * `denied` is a refusal too -- an exhausted allowance -- while `warning` comes with an answer and is kept.
	 *
	 * @param array|WP_Error $response What request() returned.
	 *
	 * @return array|WP_Error
	 */
	private function answer( array|WP_Error $response ): array|WP_Error {
		$data = $this->json( $response );

		if ( ! is_wp_error( $data ) && in_array( $data['status'] ?? '', array( 'error', 'denied' ), true ) ) {
			return $this->error( 'api_error', Field::message( $data['message'] ?? null, __( 'ProxyCheck refused the request.', 'sugarcommerce' ) ) );
		}

		return $data;
	}
}
