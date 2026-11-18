<?php
/**
 * AbuseIPDB check
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Providers\AbuseIPDB;

use SugarCommerce\IpLookup\Response;

/**
 * Class Check
 *
 * The `data` block of AbuseIPDB's `/api/v2/check` answer.
 *
 * AbuseIPDB's guidance: 75 and over is high confidence of abuse, 90 and
 * over very high.
 *
 * @since 1.0.0
 */
class Check extends Response {

	/**
	 * The abuse confidence score, 0 to 100.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	public function get_confidence_score(): int {
		return (int) ( $this->data['abuseConfidenceScore'] ?? 0 );
	}

	/**
	 * Whether the score is at or above a threshold.
	 *
	 * @since 1.0.0
	 *
	 * @param int $threshold The lowest score that counts. Default 75.
	 *
	 * @return bool
	 */
	public function is_abusive( int $threshold = 75 ): bool {
		return $this->get_confidence_score() >= $threshold;
	}

	/**
	 * How many reports there are, over the whole window.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	public function get_total_reports(): int {
		return (int) ( $this->data['totalReports'] ?? 0 );
	}

	/**
	 * How many different sites filed them.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	public function get_distinct_reporters(): int {
		return (int) ( $this->data['numDistinctUsers'] ?? 0 );
	}

	/**
	 * The country, as an upper-case ISO code.
	 *
	 * @since 1.0.0
	 *
	 * @return string Empty when unknown.
	 */
	public function get_country_code(): string {
		return strtoupper( (string) ( $this->data['countryCode'] ?? '' ) );
	}

	/**
	 * How the address is used: `Data Center/Web Hosting/Transit`, `Fixed
	 * Line ISP`...
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function get_usage_type(): string {
		return (string) ( $this->data['usageType'] ?? '' );
	}

	/**
	 * Whether it is on AbuseIPDB's public allowlist -- Google, Cloudflare,
	 * Apple and the like.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function is_whitelisted(): bool {
		return (bool) ( $this->data['isWhitelisted'] ?? false );
	}

	/**
	 * Whether it is a Tor exit node.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function is_tor(): bool {
		return (bool) ( $this->data['isTor'] ?? false );
	}

	/**
	 * Days since it was last reported, so an old score can be discounted.
	 *
	 * @since 1.0.0
	 *
	 * @return int|null Null when it never was.
	 */
	public function get_last_reported_days(): ?int {
		$last = strtotime( (string) ( $this->data['lastReportedAt'] ?? '' ) );

		if ( false === $last ) {
			return null;
		}

		return (int) floor( ( time() - $last ) / DAY_IN_SECONDS );
	}
}
