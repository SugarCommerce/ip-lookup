<?php
/**
 * ProxyCheck address answer, written out
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Traits\ProxyCheckIP;

/**
 * Trait Formatted
 *
 * The answer's parts as one line each, for a person to read: `Germany
 * (DE)`, `51.5074°N, 0.1278°W`, `Login Attempts: 5, Comment Spam: 3`.
 *
 * @since 1.0.0
 */
trait Formatted {

	/**
	 * Get formatted continent string
	 *
	 * Returns a formatted string containing continent information
	 * in the format: "Name (Code)" e.g., "North America (NA)"
	 *
	 * @return string|null Formatted continent string or null if no continent info
	 */
	public function get_formatted_continent(): ?string {
		$continent = $this->get_continent();
		if ( ! $continent ) {
			return null;
		}

		$parts = [];
		if ( ! empty( $continent['name'] ) ) {
			$parts[] = $continent['name'];
		}

		if ( ! empty( $continent['code'] ) ) {
			$parts[] = "({$continent['code']})";
		}

		return empty( $parts ) ? null : implode( ' ', $parts );
	}

	/**
	 * Get formatted country string
	 *
	 * Returns a formatted string containing country information
	 * in the format: "Name (Code) 🇪🇺" e.g., "Germany (DE) 🇪🇺"
	 *
	 * @return string|null Formatted country string or null if no country info
	 */
	public function get_formatted_country(): ?string {
		$country = $this->get_country();
		if ( ! $country ) {
			return null;
		}

		$parts = [];
		if ( ! empty( $country['name'] ) ) {
			$parts[] = $country['name'];
		}

		if ( ! empty( $country['code'] ) ) {
			$parts[] = "({$country['code']})";
		}

		if ( ! empty( $country['is_eu'] ) ) {
			$parts[] = '🇪🇺';
		}

		return empty( $parts ) ? null : implode( ' ', $parts );
	}

	/**
	 * Get formatted region string
	 *
	 * Returns a formatted string containing region information
	 * in the format: "Name (Code)" e.g., "California (CA)"
	 *
	 * @return string|null Formatted region string or null if no region info
	 */
	public function get_formatted_region(): ?string {
		$region = $this->get_region();
		if ( ! $region ) {
			return null;
		}

		$parts = [];
		if ( ! empty( $region['name'] ) ) {
			$parts[] = $region['name'];
		}

		if ( ! empty( $region['code'] ) ) {
			$parts[] = "({$region['code']})";
		}

		return empty( $parts ) ? null : implode( ' ', $parts );
	}

	/**
	 * Get formatted full address string
	 *
	 * Combines city, region, country, and postcode into a single formatted address
	 * e.g., "Los Angeles, California (CA), United States (US) 90001"
	 *
	 * @return string|null Formatted address string or null if no address info
	 */
	public function get_formatted_address(): ?string {
		$parts = array_filter( [
			$this->get_city(),
			$this->get_formatted_region(),
			$this->get_formatted_country(),
			$this->get_postcode(),
		] );

		return empty( $parts ) ? null : implode( ', ', $parts );
	}

	/**
	 * Get formatted coordinates string
	 *
	 * Returns coordinates in standard lat/long format
	 * e.g., "51.5074°N, 0.1278°W"
	 *
	 * @return string|null Formatted coordinates string or null if no coordinates
	 */
	public function get_formatted_coordinates(): ?string {
		$coordinates = $this->get_coordinates();
		if ( ! $coordinates ) {
			return null;
		}

		$lat  = $coordinates['latitude'];
		$long = $coordinates['longitude'];

		$lat_direction  = $lat >= 0 ? '°N' : '°S';
		$long_direction = $long >= 0 ? '°E' : '°W';

		return abs( $lat ) . $lat_direction . ', ' . abs( $long ) . $long_direction;
	}

	/**
	 * Get formatted currency string
	 *
	 * Returns a formatted string containing available currency information
	 * in the format: "Symbol Code (Name)" e.g., "$ USD (United States Dollar)"
	 *
	 * @param string $separator Separator between currency parts (default: ' ')
	 *
	 * @return string|null Formatted currency string or null if no currency info
	 */
	public function get_formatted_currency( string $separator = ' ' ): ?string {
		$currency = $this->get_currency();
		if ( ! $currency ) {
			return null;
		}

		$currency_parts = [];

		if ( ! empty( $currency['symbol'] ) ) {
			$currency_parts[] = $currency['symbol'];
		}

		if ( ! empty( $currency['code'] ) ) {
			$currency_parts[] = $currency['code'];
		}

		if ( ! empty( $currency['name'] ) ) {
			$currency_parts[] = "({$currency['name']})";
		}

		return empty( $currency_parts ) ? null : implode( $separator, $currency_parts );
	}

	/**
	 * Get formatted operator string
	 *
	 * Combines provider name and ASN information
	 * e.g., "Amazon Web Services (AS16509)"
	 *
	 * @return string|null Formatted operator string or null if no operator info
	 */
	public function get_formatted_operator(): ?string {
		$operator = $this->get_operator();
		if ( ! $operator ) {
			return null;
		}

		$parts = [];
		if ( ! empty( $operator['name'] ) ) {
			$parts[] = $operator['name'];
		}

		if ( ! empty( $operator['asn'] ) ) {
			$parts[] = "({$operator['asn']})";
		}

		return empty( $parts ) ? null : implode( ' ', $parts );
	}

	/**
	 * Get formatted attack history string
	 *
	 * Returns a human-readable summary of attack history
	 * e.g., "Login Attempts: 5, Comment Spam: 3"
	 *
	 * @return string|null Formatted attack history or null if no history
	 */
	public function get_formatted_attack_history(): ?string {
		$history = $this->get_attack_history();
		if ( ! $history ) {
			return null;
		}

		$parts = [];
		foreach ( $history as $type => $count ) {
			$readable_type = ucwords( str_replace( '_', ' ', $type ) );
			$parts[]       = "$readable_type: $count";
		}

		return empty( $parts ) ? null : implode( ', ', $parts );
	}

	/**
	 * Get formatted devices string
	 *
	 * Returns a human-readable summary of device counts
	 * e.g., "Address: 145, Subnet: 1024"
	 *
	 * @return string|null Formatted devices string or null if no device info
	 */
	public function get_formatted_devices(): ?string {
		$devices = $this->get_devices();
		if ( ! $devices ) {
			return null;
		}

		$parts = [];
		foreach ( $devices as $type => $count ) {
			$readable_type = ucfirst( $type );
			$parts[]       = "$readable_type: $count";
		}

		return empty( $parts ) ? null : implode( ', ', $parts );
	}
}
