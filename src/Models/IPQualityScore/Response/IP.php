<?php
/**
 * IPQualityScore ip response
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Models\IPQualityScore\Response;

use SugarCommerce\IpLookup\Support\Field;

/**
 * IP Response Class
 *
 * Represents a response from the IPQualityScore Proxy Detection API.
 * Based on the official API documentation.
 */
class IP extends Base {

	/**
	 * Get the fraud score (0-100, with 75+ as suspicious and 90+ as high risk)
	 *
	 * @return float|null
	 */
	public function get_fraud_score(): ?float {
		return Field::float( $this->data['fraud_score'] ?? null );
	}

	/**
	 * Check if IP is proxy (SOCKS, Elite, Anonymous, VPN, Tor, etc.)
	 *
	 * @return bool
	 */
	public function is_proxy(): bool {
		return (bool) ( $this->data['proxy'] ?? false );
	}

	/**
	 * Get the hostname if available
	 *
	 * @return string|null
	 */
	public function get_host(): ?string {
		return Field::text( $this->data['host'] ?? null );
	}

	/**
	 * Get the ISP if known
	 *
	 * @return string|null
	 */
	public function get_isp(): ?string {
		return Field::text( $this->data['ISP'] ?? null );
	}

	/**
	 * Get the organization if known
	 *
	 * @return string|null
	 */
	public function get_organization(): ?string {
		return Field::text( $this->data['organization'] ?? null );
	}

	/**
	 * Get the ASN (Autonomous System Number)
	 *
	 * @return int|null
	 */
	public function get_asn(): ?int {
		return Field::int( $this->data['ASN'] ?? null );
	}

	/**
	 * Get country code
	 *
	 * @return string|null
	 */
	public function get_country_code(): ?string {
		return Field::text( $this->data['country_code'] ?? null );
	}

	/**
	 * Get city
	 *
	 * @return string|null
	 */
	public function get_city(): ?string {
		return Field::text( $this->data['city'] ?? null );
	}

	/**
	 * Get region/state
	 *
	 * @return string|null
	 */
	public function get_region(): ?string {
		return Field::text( $this->data['region'] ?? null );
	}

	/**
	 * Get timezone
	 *
	 * @return string|null
	 */
	public function get_timezone(): ?string {
		return Field::text( $this->data['timezone'] ?? null );
	}

	/**
	 * Get latitude
	 *
	 * @return float|null
	 */
	public function get_latitude(): ?float {
		return Field::float( $this->data['latitude'] ?? null );
	}

	/**
	 * Get longitude
	 *
	 * @return float|null
	 */
	public function get_longitude(): ?float {
		return Field::float( $this->data['longitude'] ?? null );
	}

	/**
	 * Get zip/postal code
	 *
	 * @return string|null
	 */
	public function get_zip_code(): ?string {
		return Field::text( $this->data['zip_code'] ?? null );
	}

	/**
	 * Check if IP is a verified crawler (e.g., Googlebot, Bingbot)
	 *
	 * @return bool
	 */
	public function is_crawler(): bool {
		return (bool) ( $this->data['is_crawler'] ?? false );
	}

	/**
	 * Get connection type (Residential, Corporate, Education, Mobile, Data Center)
	 *
	 * @return string|null
	 */
	public function get_connection_type(): ?string {
		return Field::text( $this->data['connection_type'] ?? null );
	}

	/**
	 * Check if recent abuse detected
	 *
	 * @return bool
	 */
	public function has_recent_abuse(): bool {
		return (bool) ( $this->data['recent_abuse'] ?? false );
	}

	/**
	 * Get abuse velocity (high, medium, low, none)
	 *
	 * @return string|null
	 */
	public function get_abuse_velocity(): ?string {
		return Field::text( $this->data['abuse_velocity'] ?? null );
	}

	/**
	 * Check bot status
	 *
	 * @return bool
	 */
	public function is_bot(): bool {
		return (bool) ( $this->data['bot_status'] ?? false );
	}

	/**
	 * Check if IP is VPN
	 *
	 * @return bool
	 */
	public function is_vpn(): bool {
		return (bool) ( $this->data['vpn'] ?? false );
	}

	/**
	 * Check if IP is TOR
	 *
	 * @return bool
	 */
	public function is_tor(): bool {
		return (bool) ( $this->data['tor'] ?? false );
	}

	/**
	 * Check if IP is active VPN
	 *
	 * @return bool
	 */
	public function is_active_vpn(): bool {
		return (bool) ( $this->data['active_vpn'] ?? false );
	}

	/**
	 * Check if IP is active TOR
	 *
	 * @return bool
	 */
	public function is_active_tor(): bool {
		return (bool) ( $this->data['active_tor'] ?? false );
	}

	/**
	 * Check if frequent abuser (Enterprise Data Point)
	 *
	 * @return bool
	 */
	public function is_frequent_abuser(): bool {
		return (bool) ( $this->data['frequent_abuser'] ?? false );
	}

	/**
	 * Check if high risk attacks detected (Enterprise Data Point)
	 *
	 * @return bool
	 */
	public function has_high_risk_attacks(): bool {
		return (bool) ( $this->data['high_risk_attacks'] ?? false );
	}

	/**
	 * Check if shared connection (Enterprise Data Point)
	 *
	 * @return bool
	 */
	public function is_shared_connection(): bool {
		return (bool) ( $this->data['shared_connection'] ?? false );
	}

	/**
	 * Check if dynamic connection (Enterprise Data Point)
	 *
	 * @return bool
	 */
	public function is_dynamic_connection(): bool {
		return (bool) ( $this->data['dynamic_connection'] ?? false );
	}

	/**
	 * Check if security scanner (Enterprise Data Point)
	 *
	 * @return bool
	 */
	public function is_security_scanner(): bool {
		return (bool) ( $this->data['security_scanner'] ?? false );
	}

	/**
	 * Check if trusted network (Enterprise Data Point)
	 *
	 * @return bool
	 */
	public function is_trusted_network(): bool {
		return (bool) ( $this->data['trusted_network'] ?? false );
	}

	/**
	 * Check if mobile device
	 *
	 * @return bool
	 */
	public function is_mobile(): bool {
		return (bool) ( $this->data['mobile'] ?? false );
	}

	/**
	 * Get operating system info
	 *
	 * @return string|null
	 */
	public function get_operating_system(): ?string {
		return Field::text( $this->data['operating_system'] ?? null );
	}

	/**
	 * Get browser info
	 *
	 * @return string|null
	 */
	public function get_browser(): ?string {
		return Field::text( $this->data['browser'] ?? null );
	}

	/**
	 * Get device brand
	 *
	 * @return string|null
	 */
	public function get_device_brand(): ?string {
		return Field::text( $this->data['device_brand'] ?? null );
	}

	/**
	 * Get device model
	 *
	 * @return string|null
	 */
	public function get_device_model(): ?string {
		return Field::text( $this->data['device_model'] ?? null );
	}

	/**
	 * Get transaction details if available
	 *
	 * @return array|null
	 */
	public function get_transaction_details(): ?array {
		return Field::map( $this->data['transaction_details'] ?? null );
	}

	/**
	 * Helper method to get risk assessment based on fraud score
	 *
	 * @return string Returns 'Low Risk', 'Suspicious', 'High Risk', or 'Frequent Abuse' based on fraud score
	 */
	public function get_risk_level(): string {
		$score = $this->get_fraud_score();

		if ( $score === null ) {
			return 'Unknown';
		}

		if ( $score >= 90 ) {
			return 'Frequent Abuse';
		}
		if ( $score >= 85 ) {
			return 'High Risk';
		}
		if ( $score >= 75 ) {
			return 'Suspicious';
		}

		return 'Low Risk';
	}

	/**
	 * Helper method to check if the IP is considered high risk
	 *
	 * @return bool
	 */
	public function is_high_risk(): bool {
		return $this->get_fraud_score() >= 90 ||
				$this->has_high_risk_attacks() ||
				( $this->is_proxy() && $this->has_recent_abuse() );
	}
}
