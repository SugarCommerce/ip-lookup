<?php
/**
 * Result
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Models;

/**
 * Class Result
 *
 * What one provider said about one address, in the same shape whichever
 * provider it was.
 *
 * Every answer can be null, and null means the provider did not say -- not
 * "no". IPinfo has no risk score, AbuseIPDB does not know about VPNs, and a
 * plan below Business gets no privacy flags from IPinfo at all. A check
 * that reads null as false lets a VPN through because the service was
 * never asked about VPNs.
 *
 * The provider's own response, with everything this does not carry, is
 * get_response().
 *
 * @since 1.0.0
 */
final class Result {

	/**
	 * The answers this result can hold, and the type of each.
	 */
	private const array FIELDS = array(
		'risk_score'      => 'int',
		'is_proxy'        => 'bool',
		'is_vpn'          => 'bool',
		'is_tor'          => 'bool',
		'is_relay'        => 'bool',
		'is_hosting'      => 'bool',
		'is_bot'          => 'bool',
		'is_abusive'      => 'bool',
		'country_code'    => 'string',
		'region'          => 'string',
		'city'            => 'string',
		'postal_code'     => 'string',
		'continent_code'  => 'string',
		'is_eu'           => 'bool',
		'latitude'        => 'float',
		'longitude'       => 'float',
		'timezone'        => 'string',
		'asn'             => 'string',
		'isp'             => 'string',
		'organisation'    => 'string',
		'connection_type' => 'string',
	);

	/**
	 * The answers, each null when the provider did not give it.
	 *
	 * @var array<string, mixed>
	 */
	private array $fields = array();

	/**
	 * Build a result.
	 *
	 * Values are cleaned on the way in: an empty string is no answer, a
	 * country or continent code is upper case, a risk score is held to
	 * 0-100, and an ASN is written `AS15169` whichever way the provider
	 * wrote it. Keys this class does not know are ignored.
	 *
	 * @since 1.0.0
	 *
	 * @param string      $provider The provider's id.
	 * @param string      $ip       The address asked about.
	 * @param array       $fields   Answers by name: `risk_score`, `is_vpn`, `country_code`...
	 * @param object|null $response The provider's own response object.
	 */
	public function __construct(
		private readonly string $provider,
		private readonly string $ip,
		array $fields = array(),
		private readonly ?object $response = null
	) {
		foreach ( self::FIELDS as $name => $type ) {
			$this->fields[ $name ] = self::clean( $name, $type, $fields[ $name ] ?? null );
		}
	}

	/**
	 * The names of every answer a result can hold.
	 *
	 * @since 1.0.0
	 *
	 * @return string[]
	 */
	public static function fields(): array {
		return array_keys( self::FIELDS );
	}

	/**
	 * Which provider answered.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function get_provider(): string {
		return $this->provider;
	}

	/**
	 * The address asked about.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function get_ip(): string {
		return $this->ip;
	}

	/**
	 * How risky the provider thinks the address is, 0 to 100.
	 *
	 * Each provider means something slightly different: AbuseIPDB's abuse
	 * confidence, IPQualityScore's fraud score, ProxyCheck's risk, minFraud's
	 * IP risk. Compare a score with the same provider's thresholds, not
	 * another's.
	 *
	 * @since 1.0.0
	 *
	 * @return int|null
	 */
	public function get_risk_score(): ?int {
		return $this->fields['risk_score'];
	}

	/**
	 * Whether the score is at or above a threshold.
	 *
	 * @since 1.0.0
	 *
	 * @param int $threshold The lowest score that counts.
	 *
	 * @return bool|null Null when there is no score.
	 */
	public function is_high_risk( int $threshold = 75 ): ?bool {
		$score = $this->get_risk_score();

		return null === $score ? null : $score >= $threshold;
	}

	/**
	 * Whether it is a proxy.
	 *
	 * @since 1.0.0
	 *
	 * @return bool|null
	 */
	public function is_proxy(): ?bool {
		return $this->fields['is_proxy'];
	}

	/**
	 * Whether it is a VPN exit.
	 *
	 * @since 1.0.0
	 *
	 * @return bool|null
	 */
	public function is_vpn(): ?bool {
		return $this->fields['is_vpn'];
	}

	/**
	 * Whether it is a Tor exit node.
	 *
	 * @since 1.0.0
	 *
	 * @return bool|null
	 */
	public function is_tor(): ?bool {
		return $this->fields['is_tor'];
	}

	/**
	 * Whether it is a privacy relay, such as iCloud Private Relay.
	 *
	 * Mostly ordinary people on Apple devices: a soft signal, not a reason
	 * to block.
	 *
	 * @since 1.0.0
	 *
	 * @return bool|null
	 */
	public function is_relay(): ?bool {
		return $this->fields['is_relay'];
	}

	/**
	 * Whether it belongs to a hosting company or a data centre.
	 *
	 * @since 1.0.0
	 *
	 * @return bool|null
	 */
	public function is_hosting(): ?bool {
		return $this->fields['is_hosting'];
	}

	/**
	 * Whether it behaves like a bot.
	 *
	 * @since 1.0.0
	 *
	 * @return bool|null
	 */
	public function is_bot(): ?bool {
		return $this->fields['is_bot'];
	}

	/**
	 * Whether it has been reported for abuse recently enough to count.
	 *
	 * @since 1.0.0
	 *
	 * @return bool|null
	 */
	public function is_abusive(): ?bool {
		return $this->fields['is_abusive'];
	}

	/**
	 * Whether the address hides who is behind it: a proxy, a VPN or Tor.
	 *
	 * True when any of the three is true; false only when the provider
	 * answered and none is; null when it said nothing about any of them.
	 *
	 * @since 1.0.0
	 *
	 * @return bool|null
	 */
	public function is_anonymous(): ?bool {
		return self::any( $this->fields['is_proxy'], $this->fields['is_vpn'], $this->fields['is_tor'] );
	}

	/**
	 * Whether it is anonymous or in a data centre -- the usual evasions in
	 * one check.
	 *
	 * Relays are left out on purpose; see is_relay().
	 *
	 * @since 1.0.0
	 *
	 * @return bool|null
	 */
	public function is_suspicious(): ?bool {
		return self::any( $this->is_anonymous(), $this->fields['is_hosting'] );
	}

	/**
	 * The country, as an ISO 3166-1 alpha-2 code.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_country_code(): ?string {
		return $this->fields['country_code'];
	}

	/**
	 * The region or state, as the provider names it.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_region(): ?string {
		return $this->fields['region'];
	}

	/**
	 * The city. Approximate: usually right to the metro area, no closer.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_city(): ?string {
		return $this->fields['city'];
	}

	/**
	 * The postal code.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_postal_code(): ?string {
		return $this->fields['postal_code'];
	}

	/**
	 * The continent, as a two-letter code: `EU`, `NA`, `AS`...
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_continent_code(): ?string {
		return $this->fields['continent_code'];
	}

	/**
	 * Whether the country is in the European Union.
	 *
	 * @since 1.0.0
	 *
	 * @return bool|null
	 */
	public function is_eu(): ?bool {
		return $this->fields['is_eu'];
	}

	/**
	 * The latitude.
	 *
	 * @since 1.0.0
	 *
	 * @return float|null
	 */
	public function get_latitude(): ?float {
		return $this->fields['latitude'];
	}

	/**
	 * The longitude.
	 *
	 * @since 1.0.0
	 *
	 * @return float|null
	 */
	public function get_longitude(): ?float {
		return $this->fields['longitude'];
	}

	/**
	 * The time zone, as an IANA name: `Europe/London`.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_timezone(): ?string {
		return $this->fields['timezone'];
	}

	/**
	 * The network's autonomous system number, written `AS15169`.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_asn(): ?string {
		return $this->fields['asn'];
	}

	/**
	 * The internet provider.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_isp(): ?string {
		return $this->fields['isp'];
	}

	/**
	 * The organisation the address is registered to.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_organisation(): ?string {
		return $this->fields['organisation'];
	}

	/**
	 * What kind of connection it is, in lower case with no spaces:
	 * `residential`, `mobile`, `business`, `hosting`, `education`...
	 *
	 * Each provider has its own list; this is that provider's word for it,
	 * normalised so `Data Center` and `datacenter` are one value.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_connection_type(): ?string {
		return $this->fields['connection_type'];
	}

	/**
	 * The provider's own response object, with everything it said.
	 *
	 * @since 1.0.0
	 *
	 * @return object|null
	 */
	public function get_response(): ?object {
		return $this->response;
	}

	/**
	 * Every answer, by name, with the provider and the address.
	 *
	 * @since 1.0.0
	 *
	 * @return array<string, mixed>
	 */
	public function to_array(): array {
		return array(
			'provider' => $this->provider,
			'ip'       => $this->ip,
		) + $this->fields;
	}

	/**
	 * True when any answer is true, false when every answer is false, null
	 * when none was given.
	 *
	 * @param bool|null ...$answers The answers.
	 *
	 * @return bool|null
	 */
	private static function any( ?bool ...$answers ): ?bool {
		if ( in_array( true, $answers, true ) ) {
			return true;
		}

		return in_array( false, $answers, true ) ? false : null;
	}

	/**
	 * One answer, cleaned to its type.
	 *
	 * @param string $name  The answer's name.
	 * @param string $type  Its type.
	 * @param mixed  $value What the provider gave.
	 *
	 * @return mixed
	 */
	private static function clean( string $name, string $type, mixed $value ): mixed {
		if ( null === $value || ( is_string( $value ) && '' === trim( $value ) ) || is_array( $value ) || is_object( $value ) ) {
			return null;
		}

		switch ( $type ) {
			case 'bool':
				return is_bool( $value ) ? $value : filter_var( $value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE );

			case 'int':
				return is_numeric( $value ) ? max( 0, min( 100, (int) round( (float) $value ) ) ) : null;

			case 'float':
				return is_numeric( $value ) ? (float) $value : null;
		}

		$value = trim( (string) $value );

		return match ( $name ) {
			'country_code', 'continent_code' => strtoupper( $value ),
			'asn'                            => self::asn( $value ),
			'connection_type'                => strtolower( str_replace( array( ' ', '-', '_' ), '', $value ) ),
			default                          => $value,
		};
	}

	/**
	 * An ASN written one way: `AS` and the number.
	 *
	 * IPinfo writes `AS15169`, IPQualityScore `15169`, ProxyCheck `AS15169`.
	 *
	 * @param string $value The ASN as given.
	 *
	 * @return string|null
	 */
	private static function asn( string $value ): ?string {
		return 1 === preg_match( '/^(?:AS)?\s*(\d+)$/i', $value, $match ) ? 'AS' . $match[1] : null;
	}
}
