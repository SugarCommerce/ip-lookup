<?php
/**
 * ProxyCheck countries
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Traits\ProxyCheck;

/**
 * Trait Countries
 *
 * The countries a verdict blocks, and the ones it lets through whatever
 * else is wrong.
 *
 * @since 1.0.0
 */
trait Countries {

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
}
