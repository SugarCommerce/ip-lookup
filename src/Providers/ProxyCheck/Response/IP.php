<?php
/**
 * ProxyCheck address response
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Providers\ProxyCheck\Response;

use SugarCommerce\IpLookup\Support\Field;
use SugarCommerce\IpLookup\Traits\ProxyCheckIP\Formatted;
use SugarCommerce\IpLookup\Traits\ProxyCheckIP\MapLinks;

/**
 * Class IP
 *
 * ProxyCheck's answer about one address. The parts written out for a
 * person are in Formatted, the map links in MapLinks.
 *
 * @since 1.0.0
 */
class IP extends Base {

	use Formatted;
	use MapLinks;

	/**
	 * Default risk threshold for high risk determination
	 */
	private const int RISK_HIGH_THRESHOLD = 70;

	/**
	 * Get the IP address that was checked
	 *
	 * @return string|null
	 */
	public function get_ip(): ?string {
		return $this->identifier ?? null;
	}

	/**
	 * Check if the IP is a proxy
	 *
	 * @return bool
	 */
	public function is_proxy(): bool {
		return 'yes' === ( $this->entry()['proxy'] ?? null );
	}

	/**
	 * Get the proxy type (e.g., 'Residential', 'VPN', etc.)
	 *
	 * @return string|null
	 */
	public function get_type(): ?string {
		return $this->entry_text( 'type' );
	}

	/**
	 * Get the provider name
	 *
	 * @return string|null
	 */
	public function get_provider(): ?string {
		return $this->entry_text( 'provider' );
	}

	/**
	 * Get the organization name
	 *
	 * @return string|null
	 */
	public function get_organisation(): ?string {
		return $this->entry_text( 'organisation' );
	}

	/**
	 * Get the risk score (0-100)
	 *
	 * @return int|null
	 */
	public function get_risk_score(): ?int {
		return Field::int( $this->entry()['risk'] ?? null );
	}

	/**
	 * The connection underneath: `Hosting`, `Residential`, `Mobile`,
	 * `Business`. Asked for with the network flag.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_network_type(): ?string {
		return Field::text( Field::map( $this->entry()['network'] ?? null )['type'] ?? null );
	}

	/**
	 * Get the hostname if available
	 *
	 * @return string|null
	 */
	public function get_hostname(): ?string {
		return $this->entry_text( 'hostname' );
	}

	/**
	 * Get the IP range
	 *
	 * @return string|null
	 */
	public function get_range(): ?string {
		return $this->entry_text( 'range' );
	}

	/**
	 * Get ASN information
	 *
	 * @return string|null
	 */
	public function get_asn(): ?string {
		return $this->entry_text( 'asn' );
	}

	/**
	 * Get device information
	 *
	 * @return array|null
	 */
	public function get_devices(): ?array {
		$devices = Field::map( $this->entry()['devices'] ?? null );

		if ( null === $devices ) {
			return null;
		}

		return [
			'address' => Field::int( $devices['address'] ?? null ) ?? 0,
			'subnet'  => Field::int( $devices['subnet'] ?? null ) ?? 0,
		];
	}

	/**
	 * Get attack history data
	 * Only available when risk=2 flag is used
	 *
	 * @return array|null
	 */
	public function get_attack_history(): ?array {
		$history      = [];
		$attack_types = [
			'login_attempts',
			'registration_attempts',
			'comment_spam',
			'denial_of_service',
			'forum_spam',
			'form_submission',
			'vulnerability_probing',
		];

		foreach ( $attack_types as $type ) {
			$count = Field::int( $this->entry()[ $type ] ?? null );

			if ( null !== $count ) {
				$history[ $type ] = $count;
			}
		}

		return ! empty( $history ) ? $history : null;
	}

	/**
	 * Get the port number if detected
	 *
	 * @return int|null
	 */
	public function get_port(): ?int {
		return Field::int( $this->entry()['port'] ?? null );
	}

	/**
	 * Get when this proxy was last seen
	 *
	 * @return string|null
	 */
	public function get_last_seen(): ?string {
		return $this->entry_text( 'seen' );
	}

	/**
	 * Get the operator/ASN information
	 *
	 * @return array|null
	 */
	public function get_operator(): ?array {
		$operator = [];

		if ( null !== $this->get_provider() ) {
			$operator['name'] = $this->get_provider();
		}

		if ( null !== $this->get_asn() ) {
			$operator['asn'] = $this->get_asn();
		}

		return ! empty( $operator ) ? $operator : null;
	}

	/**
	 * Get continent information
	 *
	 * @return array|null
	 */
	public function get_continent(): ?array {
		if ( null === $this->entry_text( 'continent' ) ) {
			return null;
		}

		return [
			'name' => $this->entry_text( 'continent' ),
			'code' => $this->entry_text( 'continentcode' ),
		];
	}

	/**
	 * Get country information
	 *
	 * @return array|null
	 */
	public function get_country(): ?array {
		if ( null === $this->entry_text( 'country' ) ) {
			return null;
		}

		return [
			'name'  => $this->entry_text( 'country' ),
			'code'  => $this->entry_text( 'isocode' ),
			'is_eu' => 1 === ( $this->entry()['europe'] ?? null ),
		];
	}

	/**
	 * Get region information
	 *
	 * @return array|null
	 */
	public function get_region(): ?array {
		if ( null === $this->entry_text( 'region' ) ) {
			return null;
		}

		return [
			'name' => $this->entry_text( 'region' ),
			'code' => $this->entry_text( 'regioncode' ),
		];
	}

	/**
	 * Get city name
	 *
	 * @return string|null
	 */
	public function get_city(): ?string {
		return $this->entry_text( 'city' );
	}

	/**
	 * Get postal/zip code
	 *
	 * @return string|null
	 */
	public function get_postcode(): ?string {
		return $this->entry_text( 'postcode' );
	}

	/**
	 * Get location coordinates
	 *
	 * @return array|null
	 */
	public function get_coordinates(): ?array {
		$latitude  = Field::float( $this->entry()['latitude'] ?? null );
		$longitude = Field::float( $this->entry()['longitude'] ?? null );

		if ( null === $latitude || null === $longitude ) {
			return null;
		}

		return [
			'latitude'  => $latitude,
			'longitude' => $longitude,
		];
	}

	/**
	 * Get currency information
	 *
	 * @return array|null
	 */
	public function get_currency(): ?array {
		$currency = Field::map( $this->entry()['currency'] ?? null );

		if ( null === $currency ) {
			return null;
		}

		return [
			'code'   => Field::text( $currency['code'] ?? null ),
			'name'   => Field::text( $currency['name'] ?? null ),
			'symbol' => Field::text( $currency['symbol'] ?? null ),
		];
	}

	/**
	 * Get timezone information
	 *
	 * @return string|null
	 */
	public function get_timezone(): ?string {
		return $this->entry_text( 'timezone' );
	}

	/**
	 * Determine if this is a VPN
	 * Only available when vpn flag is used
	 *
	 * @return bool|null
	 */
	public function is_vpn(): ?bool {
		$type = $this->get_type();

		return $type !== null ? strtolower( $type ) === 'vpn' : null;
	}

	/**
	 * Get operator details including anonymity, popularity and protocols
	 *
	 * @return array|null Array of operator details or null if not available
	 */
	public function get_operator_details(): ?array {
		$operator = Field::map( $this->entry()['operator'] ?? null );

		if ( null === $operator ) {
			return null;
		}

		return [
			'name'       => Field::text( $operator['name'] ?? null ),
			'url'        => $operator['url'] ?? null,
			'anonymity'  => Field::text( $operator['anonymity'] ?? null ),
			'popularity' => Field::text( $operator['popularity'] ?? null ),
			'protocols'  => Field::map( $operator['protocols'] ?? null ) ?? [],
			'policies'   => Field::map( $operator['policies'] ?? null ) ?? [],
		];
	}

	/**
	 * Get VPN operator policies if available
	 *
	 * @return array|null Array of operator policies or null if not available
	 */
	public function get_operator_policies(): ?array {
		return Field::map( Field::map( $this->entry()['operator'] ?? null )['policies'] ?? null );
	}

	/**
	 * Check if this is a high risk IP
	 *
	 * @param int $threshold Risk score threshold (default: 70)
	 *
	 * @return bool True if risk score exceeds threshold
	 */
	public function is_high_risk( int $threshold = self::RISK_HIGH_THRESHOLD ): bool {
		return ( $this->get_risk_score() ?? 0 ) > $threshold;
	}
}
