<?php
/**
 * IPinfo response
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Providers\IPInfo;

use SugarCommerce\Geo\Countries;
use SugarCommerce\IpLookup\Response as Base;

/**
 * Class Response
 *
 * IPinfo's answer for one address. What it holds depends on the plan the
 * key is on: the free plan has the location and `org`, Basic adds the ASN,
 * Business the company, privacy and abuse blocks, Premium the domains.
 *
 * @since 1.0.0
 */
class Response extends Base {

	/**
	 * Which plan the answer looks like it came from.
	 *
	 * @since 1.0.0
	 *
	 * @return string `Free`, `Basic`, `Business` or `Premium`.
	 */
	public function get_plan(): string {
		if ( isset( $this->data['domains'] ) ) {
			return 'Premium';
		}

		if ( isset( $this->data['privacy'] ) || isset( $this->data['abuse'] ) || isset( $this->data['company'] ) ) {
			return 'Business';
		}

		return isset( $this->data['asn'] ) ? 'Basic' : 'Free';
	}

	/**
	 * Whether the plan includes a block of data.
	 *
	 * @since 1.0.0
	 *
	 * @param string $feature `asn`, `privacy`, `abuse`, `company` or `domains`.
	 *
	 * @return bool
	 */
	public function has_feature( string $feature ): bool {
		$plan = $this->get_plan();

		return match ( $feature ) {
			'asn'                         => in_array( $plan, array( 'Basic', 'Business', 'Premium' ), true ),
			'privacy', 'abuse', 'company' => in_array( $plan, array( 'Business', 'Premium' ), true ),
			'domains'                     => 'Premium' === $plan,
			default                       => false,
		};
	}

	/**
	 * The address.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_ip(): ?string {
		return $this->text( 'ip' );
	}

	/**
	 * The reverse DNS name.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_hostname(): ?string {
		return $this->text( 'hostname' );
	}

	/**
	 * Whether the address is anycast.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function is_anycast(): bool {
		return (bool) ( $this->data['anycast'] ?? false );
	}

	/**
	 * The city.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_city(): ?string {
		return $this->text( 'city' );
	}

	/**
	 * The region or state, by name.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_region(): ?string {
		return $this->text( 'region' );
	}

	/**
	 * The country code.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_country(): ?string {
		$country = $this->text( 'country' );

		return null === $country ? null : strtoupper( $country );
	}

	/**
	 * The country's name, in the site's language where sugarcommerce/geo
	 * has it.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_country_name(): ?string {
		$code = $this->get_country();

		return null !== $code && Countries::exists( $code ) ? Countries::get_name( $code ) : null;
	}

	/**
	 * The country's flag, as an emoji.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_country_flag(): ?string {
		$code = $this->get_country();

		return null === $code ? null : ( Countries::get_flag( $code ) ?: null );
	}

	/**
	 * The continent the country is in.
	 *
	 * @since 1.0.0
	 *
	 * @return array{code: string, name: string}|null
	 */
	public function get_continent(): ?array {
		$code = $this->get_country();
		$name = null === $code ? null : Countries::get_continent( $code );

		if ( null === $name ) {
			return null;
		}

		return array(
			'code' => (string) Countries::get_continent_code( $name ),
			'name' => $name,
		);
	}

	/**
	 * Whether the country is in the European Union.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function is_eu(): bool {
		$code = $this->get_country();

		return null !== $code && Countries::is_eu( $code );
	}

	/**
	 * The postal code.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_postal(): ?string {
		return $this->text( 'postal' );
	}

	/**
	 * The time zone.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_timezone(): ?string {
		return $this->text( 'timezone' );
	}

	/**
	 * Where the address is, as latitude and longitude.
	 *
	 * Read from `latitude` and `longitude` when the answer has them, and
	 * from `loc` -- `"37.4056,-122.0775"` -- when it does not.
	 *
	 * @since 1.0.0
	 *
	 * @return array{latitude: float, longitude: float}|null
	 */
	public function get_coordinates(): ?array {
		if ( isset( $this->data['latitude'], $this->data['longitude'] ) && is_numeric( $this->data['latitude'] ) && is_numeric( $this->data['longitude'] ) ) {
			return array(
				'latitude'  => (float) $this->data['latitude'],
				'longitude' => (float) $this->data['longitude'],
			);
		}

		$parts = explode( ',', (string) ( $this->data['loc'] ?? '' ) );

		if ( 2 !== count( $parts ) || ! is_numeric( trim( $parts[0] ) ) || ! is_numeric( trim( $parts[1] ) ) ) {
			return null;
		}

		return array(
			'latitude'  => (float) trim( $parts[0] ),
			'longitude' => (float) trim( $parts[1] ),
		);
	}

	/**
	 * The latitude.
	 *
	 * @since 1.0.0
	 *
	 * @return float|null
	 */
	public function get_latitude(): ?float {
		return $this->get_coordinates()['latitude'] ?? null;
	}

	/**
	 * The longitude.
	 *
	 * @since 1.0.0
	 *
	 * @return float|null
	 */
	public function get_longitude(): ?float {
		return $this->get_coordinates()['longitude'] ?? null;
	}

	/**
	 * The organisation line: the ASN and its name, `AS15169 Google LLC`.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_org(): ?string {
		return $this->text( 'org' );
	}

	/**
	 * The network. Basic plan and above.
	 *
	 * @since 1.0.0
	 *
	 * @return ASN|null
	 */
	public function get_asn(): ?ASN {
		return is_array( $this->data['asn'] ?? null ) ? new ASN( $this->data['asn'] ) : null;
	}

	/**
	 * The company. Business plan and above.
	 *
	 * @since 1.0.0
	 *
	 * @return Company|null
	 */
	public function get_company(): ?Company {
		return is_array( $this->data['company'] ?? null ) ? new Company( $this->data['company'] ) : null;
	}

	/**
	 * The privacy flags. Business plan and above.
	 *
	 * @since 1.0.0
	 *
	 * @return Privacy|null
	 */
	public function get_privacy(): ?Privacy {
		return is_array( $this->data['privacy'] ?? null ) ? new Privacy( $this->data['privacy'] ) : null;
	}

	/**
	 * The abuse contact. Business plan and above.
	 *
	 * @since 1.0.0
	 *
	 * @return Abuse|null
	 */
	public function get_abuse(): ?Abuse {
		return is_array( $this->data['abuse'] ?? null ) ? new Abuse( $this->data['abuse'] ) : null;
	}

	/**
	 * The domains hosted on it. Premium plan.
	 *
	 * @since 1.0.0
	 *
	 * @return Domains|null
	 */
	public function get_domains(): ?Domains {
		return is_array( $this->data['domains'] ?? null ) ? new Domains( $this->data['domains'] ) : null;
	}

	/**
	 * A text field, or null when it is missing or empty.
	 *
	 * @param string $key The field.
	 *
	 * @return string|null
	 */
	private function text( string $key ): ?string {
		$value = $this->data[ $key ] ?? null;

		return is_scalar( $value ) && '' !== (string) $value ? (string) $value : null;
	}
}
