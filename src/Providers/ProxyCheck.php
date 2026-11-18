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

use SugarCommerce\IpLookup\Providers\ProxyCheck\Response\DisposableEmail;
use SugarCommerce\IpLookup\Providers\ProxyCheck\Response\IP;
use SugarCommerce\IpLookup\Result;
use SugarCommerce\IpLookup\Provider;
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
 * @since 1.0.0
 */
class ProxyCheck extends Service implements Provider {

	protected const ID = 'proxycheck';

	protected const NAME = 'ProxyCheck';

	protected const CACHE_GROUP = 'iplookup';

	protected const CACHE_TTL = 600;

	/**
	 * The API.
	 */
	private const API_BASE = 'https://proxycheck.io/v2/';

	/**
	 * Addresses per batch request without a key.
	 */
	public const BATCH_MAX_SIZE = 100;

	/**
	 * Addresses per batch request with one.
	 */
	public const BATCH_MAX_SIZE_REGISTERED = 1000;

	/**
	 * The risk above which an address is blocked.
	 */
	public const BLOCK_RISK = 70;

	/**
	 * The query flags sent with every check.
	 *
	 * @var array<string, int|string>
	 */
	private array $parameters = array(
		'vpn'           => 0,
		'asn'           => 0,
		'node'          => 0,
		'time'          => 0,
		'inf'           => 0,
		'risk'          => 0,
		'port'          => 0,
		'seen'          => 0,
		'days'          => 7,
		'tag'           => '',
		'ver'           => 2,
		'mask'          => 0,
		'query_tagging' => 0,
	);

	/**
	 * Countries to block, upper case.
	 *
	 * @var string[]
	 */
	private array $blocked_countries = array();

	/**
	 * Countries to let through even when blocked otherwise, upper case.
	 *
	 * @var string[]
	 */
	private array $allowed_countries = array();

	/**
	 * Every query flag, as it will be sent.
	 *
	 * @since 1.0.0
	 *
	 * @return array<string, int|string>
	 */
	public function get_parameters(): array {
		return $this->parameters;
	}

	/**
	 * How hard to look for VPNs: 0 off, 1 on, 2 with the operator's name, 3
	 * with its policies.
	 *
	 * @since 1.0.0
	 *
	 * @param int $mode 0 to 3.
	 *
	 * @return static|WP_Error
	 */
	public function set_vpn( int $mode ): static|WP_Error {
		if ( $mode < 0 || $mode > 3 ) {
			return $this->error( 'invalid_vpn_mode', __( 'The VPN mode is 0 to 3.', 'sugarcommerce' ) );
		}

		$this->parameters['vpn'] = $mode;

		return $this;
	}

	/**
	 * The VPN mode.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	public function get_vpn(): int {
		return (int) $this->parameters['vpn'];
	}

	/**
	 * Ask for the network, the location and the provider.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $enable Whether to.
	 *
	 * @return static
	 */
	public function set_asn( bool $enable ): static {
		return $this->flag( 'asn', $enable );
	}

	/**
	 * Whether the network is asked for.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function get_asn(): bool {
		return (bool) $this->parameters['asn'];
	}

	/**
	 * Ask which node answered.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $enable Whether to.
	 *
	 * @return static
	 */
	public function set_node( bool $enable ): static {
		return $this->flag( 'node', $enable );
	}

	/**
	 * Whether the node is asked for.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function get_node(): bool {
		return (bool) $this->parameters['node'];
	}

	/**
	 * Ask how long the query took.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $enable Whether to.
	 *
	 * @return static
	 */
	public function set_time( bool $enable ): static {
		return $this->flag( 'time', $enable );
	}

	/**
	 * Whether the query time is asked for.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function get_time(): bool {
		return (bool) $this->parameters['time'];
	}

	/**
	 * Ask for real-time inference, which catches proxies not yet listed.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $enable Whether to.
	 *
	 * @return static
	 */
	public function set_inf( bool $enable ): static {
		return $this->flag( 'inf', $enable );
	}

	/**
	 * Whether inference is asked for.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function get_inf(): bool {
		return (bool) $this->parameters['inf'];
	}

	/**
	 * Ask for a risk score: 0 off, 1 the score, 2 the score and attack
	 * history.
	 *
	 * @since 1.0.0
	 *
	 * @param int $level 0 to 2.
	 *
	 * @return static|WP_Error
	 */
	public function set_risk( int $level ): static|WP_Error {
		if ( $level < 0 || $level > 2 ) {
			return $this->error( 'invalid_risk_level', __( 'The risk level is 0 to 2.', 'sugarcommerce' ) );
		}

		$this->parameters['risk'] = $level;

		return $this;
	}

	/**
	 * The risk level.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	public function get_risk(): int {
		return (int) $this->parameters['risk'];
	}

	/**
	 * Ask which port the proxy was seen on.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $enable Whether to.
	 *
	 * @return static
	 */
	public function set_port( bool $enable ): static {
		return $this->flag( 'port', $enable );
	}

	/**
	 * Whether the port is asked for.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function get_port(): bool {
		return (bool) $this->parameters['port'];
	}

	/**
	 * Ask when the proxy was last seen.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $enable Whether to.
	 *
	 * @return static
	 */
	public function set_seen( bool $enable ): static {
		return $this->flag( 'seen', $enable );
	}

	/**
	 * Whether last seen is asked for.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function get_seen(): bool {
		return (bool) $this->parameters['seen'];
	}

	/**
	 * How many days back a detection counts.
	 *
	 * @since 1.0.0
	 *
	 * @param int $days At least 1.
	 *
	 * @return static|WP_Error
	 */
	public function set_days( int $days ): static|WP_Error {
		if ( $days < 1 ) {
			return $this->error( 'invalid_days', __( 'Days must be at least 1.', 'sugarcommerce' ) );
		}

		$this->parameters['days'] = $days;

		return $this;
	}

	/**
	 * How many days back a detection counts.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	public function get_days(): int {
		return (int) $this->parameters['days'];
	}

	/**
	 * Tag every query, so the dashboard shows where it came from. With no
	 * tag set, the site's name is the tag.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $enable Whether to.
	 *
	 * @return static
	 */
	public function set_query_tagging( bool $enable ): static {
		$this->flag( 'query_tagging', $enable );

		if ( $enable && '' === $this->parameters['tag'] && function_exists( 'get_bloginfo' ) ) {
			$this->parameters['tag'] = sanitize_text_field( (string) get_bloginfo( 'name' ) );
		}

		return $this;
	}

	/**
	 * Whether queries are tagged.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function get_query_tagging(): bool {
		return (bool) $this->parameters['query_tagging'];
	}

	/**
	 * The tag queries are sent with.
	 *
	 * @since 1.0.0
	 *
	 * @param string $tag The tag.
	 *
	 * @return static
	 */
	public function set_tag( string $tag ): static {
		$this->parameters['tag'] = $tag;

		return $this;
	}

	/**
	 * The tag queries are sent with.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function get_tag(): string {
		return (string) $this->parameters['tag'];
	}

	/**
	 * Countries to block, by code or by ProxyCheck's name for them.
	 *
	 * Turns the network flag on, since the country comes with it.
	 *
	 * @since 1.0.0
	 *
	 * @param string[] $countries The countries.
	 *
	 * @return static
	 */
	public function set_blocked_countries( array $countries ): static {
		$this->blocked_countries = array_map( 'strtoupper', array_map( 'strval', $countries ) );

		if ( array() !== $countries ) {
			$this->set_asn( true );
		}

		return $this;
	}

	/**
	 * The countries blocked.
	 *
	 * @since 1.0.0
	 *
	 * @return string[]
	 */
	public function get_blocked_countries(): array {
		return $this->blocked_countries;
	}

	/**
	 * Whether a country is blocked.
	 *
	 * @since 1.0.0
	 *
	 * @param string $country A code or a name.
	 *
	 * @return bool
	 */
	public function is_country_blocked( string $country ): bool {
		return in_array( strtoupper( $country ), $this->blocked_countries, true );
	}

	/**
	 * Countries let through whatever else is wrong.
	 *
	 * @since 1.0.0
	 *
	 * @param string[] $countries The countries.
	 *
	 * @return static
	 */
	public function set_allowed_countries( array $countries ): static {
		$this->allowed_countries = array_map( 'strtoupper', array_map( 'strval', $countries ) );

		return $this;
	}

	/**
	 * The countries let through.
	 *
	 * @since 1.0.0
	 *
	 * @return string[]
	 */
	public function get_allowed_countries(): array {
		return $this->allowed_countries;
	}

	/**
	 * Whether a country is let through.
	 *
	 * @since 1.0.0
	 *
	 * @param string $country A code or a name.
	 *
	 * @return bool
	 */
	public function is_country_allowed( string $country ): bool {
		return in_array( strtoupper( $country ), $this->allowed_countries, true );
	}

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
		$ip = trim( $ip );

		if ( ! self::is_lookupable( $ip ) ) {
			return $this->invalid_ip( $ip );
		}

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
		$ips = array_values( array_unique( array_filter( array_map( 'trim', array_map( 'strval', $ips ) ), array( self::class, 'is_lookupable' ) ) ) );

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
		$raw         = $check->to_array()[ trim( $ip ) ] ?? array();
		$network     = is_array( $raw['network']['type'] ?? null ) ? null : ( $raw['network']['type'] ?? null );

		return new Result(
			self::ID,
			trim( $ip ),
			array(
				'risk_score'      => $check->get_risk_score(),
				'is_proxy'        => $check->is_proxy(),
				'is_vpn'          => $check->is_proxy() ? 'VPN' === $type : false,
				'is_tor'          => $check->is_proxy() ? 'TOR' === $type : false,
				'is_hosting'      => null === $network ? null : 'hosting' === strtolower( (string) $network ),
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
	 * Turn a 0/1 flag on or off.
	 *
	 * @param string $name   The flag.
	 * @param bool   $enable Whether it is on.
	 *
	 * @return static
	 */
	private function flag( string $name, bool $enable ): static {
		$this->parameters[ $name ] = $enable ? 1 : 0;

		return $this;
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
			return $this->error( 'api_error', (string) ( $data['message'] ?? __( 'ProxyCheck refused the request.', 'sugarcommerce' ) ) );
		}

		return $data;
	}

	/**
	 * Add the verdict: `block`, `block_reason` and, for a VPN, which one.
	 *
	 * @param array  $response The answer.
	 * @param string $address  The address or email it is about.
	 *
	 * @return array
	 */
	private function add_block_status( array $response, string $address ): array {
		$entry = is_array( $response[ $address ] ?? null ) ? $response[ $address ] : array();

		if ( str_contains( $address, '@' ) ) {
			$disposable               = 'yes' === ( $entry['disposable'] ?? null );
			$response['block']        = $disposable ? 'yes' : 'no';
			$response['block_reason'] = $disposable ? 'disposable' : 'na';

			return $response;
		}

		$response['block']        = 'no';
		$response['block_reason'] = 'na';

		if ( 'yes' === ( $entry['proxy'] ?? null ) ) {
			$response['block']        = 'yes';
			$response['block_reason'] = 'VPN' === ( $entry['type'] ?? null ) ? 'vpn' : 'proxy';

			if ( isset( $entry['operator'] ) && is_array( $entry['operator'] ) ) {
				$response['block_details'] = array(
					'name'       => $entry['operator']['name'] ?? '',
					'anonymity'  => $entry['operator']['anonymity'] ?? '',
					'popularity' => $entry['operator']['popularity'] ?? '',
				);
			}
		}

		if ( isset( $entry['risk'] ) && (int) $entry['risk'] > self::BLOCK_RISK ) {
			$response['block'] = 'yes';

			if ( 'na' === $response['block_reason'] ) {
				$response['block_reason'] = 'high_risk';
			}
		}

		return $this->apply_country_rules( $response, $entry );
	}

	/**
	 * Block a blocked country, then let an allowed one through.
	 *
	 * @param array $response The answer, with its verdict so far.
	 * @param array $entry    What it says about the address.
	 *
	 * @return array
	 */
	private function apply_country_rules( array $response, array $entry ): array {
		if ( ! isset( $entry['country'] ) ) {
			// Nothing to judge a country by. A proxy is still a proxy, but a
			// clean answer is no answer when the client judges by country.
			if ( 'no' === $response['block'] && array() !== $this->blocked_countries ) {
				$response['block']        = 'na';
				$response['block_reason'] = 'na';
			}

			return $response;
		}

		$names = array( strtoupper( (string) $entry['country'] ), strtoupper( (string) ( $entry['isocode'] ?? '' ) ) );

		if ( 'no' === $response['block'] && array() !== array_intersect( $names, $this->blocked_countries ) ) {
			$response['block']        = 'yes';
			$response['block_reason'] = 'country';
		}

		if ( 'yes' === $response['block'] && array() !== array_intersect( $names, $this->allowed_countries ) ) {
			$response['block']        = 'no';
			$response['block_reason'] = 'na';
		}

		return $response;
	}
}
