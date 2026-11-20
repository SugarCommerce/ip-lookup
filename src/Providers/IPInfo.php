<?php
/**
 * IPinfo
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Providers;

use SugarCommerce\IpLookup\Providers\IPInfo\Response;
use SugarCommerce\IpLookup\Result;
use SugarCommerce\IpLookup\Provider;
use SugarCommerce\IpLookup\Support\Address;
use SugarCommerce\Network\Remote\Service;
use WP_Error;

/**
 * Class IPInfo
 *
 * IPinfo (https://ipinfo.io/developers): where an address is, whose network
 * it is on, and -- on the Business plan -- whether it is a VPN, proxy, Tor
 * exit, relay or data centre.
 *
 * @since 1.0.0
 */
class IPInfo extends Service implements Provider {

	protected const string ID = 'ipinfo';

	protected const string NAME = 'IPinfo';

	protected const string CACHE_GROUP = 'iplookup';

	/**
	 * The API.
	 */
	private const string API_BASE = 'https://ipinfo.io/';

	/**
	 * The most addresses one batch request takes.
	 */
	public const int BATCH_MAX_SIZE = 1000;

	/**
	 * Seconds a batch request may take, by default.
	 */
	private const int BATCH_TIMEOUT = 5;

	/**
	 * Everything IPinfo knows about an address.
	 *
	 * @since 1.0.0
	 *
	 * @param string $ip The address.
	 *
	 * @return Response|WP_Error
	 */
	public function get_ip_info( string $ip ): Response|WP_Error {
		$address = Address::canonical( $ip );

		if ( null === $address ) {
			return $this->invalid_ip( trim( $ip ) );
		}

		$ip = $address;

		$data = $this->remember( $ip, fn () => $this->json_answer( $this->request( 'GET', self::API_BASE . rawurlencode( $ip ), $this->auth() ) ) );

		return is_wp_error( $data ) ? $data : new Response( $data );
	}

	/**
	 * Many addresses at once, in batches of up to 1,000.
	 *
	 * Addresses already cached are not asked again; addresses not worth
	 * asking about are left out.
	 *
	 * @since 1.0.0
	 *
	 * @param string[] $ips        The addresses.
	 * @param int      $batch_size Addresses per request, at most 1,000.
	 * @param bool     $filter     Ask for one field only (IPinfo's `filter=1`).
	 * @param int      $timeout    Seconds each request may take.
	 *
	 * @return array<string, Response>|WP_Error Keyed by address.
	 */
	public function get_batch_info( array $ips, int $batch_size = self::BATCH_MAX_SIZE, bool $filter = false, int $timeout = self::BATCH_TIMEOUT ): array|WP_Error {
		$ips = Address::canonical_list( $ips );

		if ( empty( $ips ) ) {
			return $this->error( 'invalid_ips', __( 'No public IP addresses to look up.', 'sugarcommerce' ) );
		}

		$results   = array();
		$remaining = array();

		foreach ( $ips as $ip ) {
			$cached = $this->is_cache_enabled() ? get_transient( $this->cache_key( $ip ) ) : false;

			if ( is_array( $cached ) && is_array( $cached['answer'] ?? null ) ) {
				$results[ $ip ] = new Response( $cached['answer'] );
			} else {
				$remaining[] = $ip;
			}
		}

		foreach ( array_chunk( $remaining, min( max( 1, $batch_size ), self::BATCH_MAX_SIZE ) ) as $batch ) {
			$answer = $this->json_answer(
				$this->request(
					'POST',
					self::API_BASE . 'batch' . ( $filter ? '?filter=1' : '' ),
					$this->auth(
						array(
							'headers' => array( 'Content-Type' => 'application/json' ),
							'body'    => (string) wp_json_encode( $batch ),
							'timeout' => $timeout,
						)
					)
				)
			);

			if ( is_wp_error( $answer ) ) {
				return $answer;
			}

			foreach ( $answer as $ip => $data ) {
				if ( ! is_array( $data ) ) {
					continue;
				}

				// Kept as a single lookup would have kept it; none was cached.
				$this->remember( (string) $ip, static fn () => $data );

				$results[ (string) $ip ] = new Response( $data );
			}
		}

		return $results;
	}

	/**
	 * One field for an address: `country`, `city`, `org`...
	 *
	 * IPinfo answers these in plain text, not JSON.
	 *
	 * @since 1.0.0
	 *
	 * @param string $ip    The address.
	 * @param string $field The field.
	 *
	 * @return string|WP_Error
	 */
	public function get_field( string $ip, string $field ): string|WP_Error {
		$address = Address::canonical( $ip );

		if ( null === $address ) {
			return $this->invalid_ip( trim( $ip ) );
		}

		$ip = $address;

		$field = trim( $field, " /\t\n\r\0\x0B" );

		if ( '' === $field || 1 !== preg_match( '/^[a-z_]+$/', $field ) ) {
			return $this->error( 'invalid_field', __( 'Not an IPinfo field.', 'sugarcommerce' ) );
		}

		return $this->remember(
			$ip . '/' . $field,
			function () use ( $ip, $field ) {
				$response = $this->request( 'GET', self::API_BASE . rawurlencode( $ip ) . '/' . $field, $this->auth( array( 'headers' => array( 'Accept' => 'text/plain' ) ) ) );

				if ( is_wp_error( $response ) ) {
					return $response;
				}

				if ( 200 !== $response['status'] ) {
					return $this->error(
						'api_error',
						/* translators: %d: the HTTP status code. */
						sprintf( __( 'IPinfo returned HTTP %d.', 'sugarcommerce' ), $response['status'] ),
						array( 'status' => $response['status'] )
					);
				}

				return trim( $response['body'], "\" \t\n\r\0\x0B" );
			}
		);
	}

	/**
	 * Several fields for an address, by name.
	 *
	 * @since 1.0.0
	 *
	 * @param string   $ip     The address.
	 * @param string[] $fields The fields.
	 *
	 * @return array<string, string>|WP_Error
	 */
	public function get_fields( string $ip, array $fields ): array|WP_Error {
		$values = array();

		foreach ( $fields as $field ) {
			$value = $this->get_field( $ip, (string) $field );

			if ( is_wp_error( $value ) ) {
				return $value;
			}

			$values[ (string) $field ] = $value;
		}

		return $values;
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
		$info = $this->get_ip_info( $ip );

		if ( is_wp_error( $info ) ) {
			return $info;
		}

		$privacy   = $info->get_privacy();
		$asn       = $info->get_asn();
		$continent = $info->get_continent();

		// The free plan has no ASN block, but its `org` starts with the ASN.
		$org = (string) $info->get_org();
		preg_match( '/^(AS\d+)\s+(.*)$/', $org, $match );

		return new Result(
			self::ID,
			Address::canonical( $ip ) ?? trim( $ip ),
			array(
				'is_proxy'        => $privacy?->is_proxy(),
				'is_vpn'          => $privacy?->is_vpn(),
				'is_tor'          => $privacy?->is_tor(),
				'is_relay'        => $privacy?->is_relay(),
				'is_hosting'      => $privacy?->is_hosting() ?? ( null === $asn?->get_type() ? null : 'hosting' === $asn->get_type() ),
				'country_code'    => $info->get_country(),
				'region'          => $info->get_region(),
				'city'            => $info->get_city(),
				'postal_code'     => $info->get_postal(),
				'continent_code'  => $continent['code'] ?? null,
				'is_eu'           => null === $info->get_country() ? null : $info->is_eu(),
				'latitude'        => $info->get_latitude(),
				'longitude'       => $info->get_longitude(),
				'timezone'        => $info->get_timezone(),
				'asn'             => $asn?->get_asn() ?? ( $match[1] ?? null ),
				'isp'             => $asn?->get_name() ?? ( $match[2] ?? null ),
				'organisation'    => $info->get_company()?->get_name() ?? ( $match[2] ?? null ),
				'connection_type' => $asn?->get_type(),
			),
			$info
		);
	}

	/**
	 * Request arguments with the key in them.
	 *
	 * Without a key IPinfo still answers, on its free allowance.
	 *
	 * @param array $args Arguments to add to.
	 *
	 * @return array
	 */
	private function auth( array $args = array() ): array {
		if ( '' === $this->api_key ) {
			return $args;
		}

		return array_replace_recursive( array( 'headers' => array( 'Authorization' => 'Bearer ' . $this->api_key ) ), $args );
	}

	/**
	 * A JSON answer, or the error IPinfo put in it.
	 *
	 * @param array|WP_Error $response What request() returned.
	 *
	 * @return array|WP_Error
	 */
	private function json_answer( array|WP_Error $response ): array|WP_Error {
		$data = $this->json( $response );

		if ( ! is_wp_error( $data ) && isset( $data['error'] ) ) {
			return $this->error( 'api_error', (string) ( $data['error']['message'] ?? __( 'Unknown IPinfo error.', 'sugarcommerce' ) ) );
		}

		return $data;
	}
}
