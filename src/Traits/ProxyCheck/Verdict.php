<?php
/**
 * ProxyCheck verdict
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Traits\ProxyCheck;

/**
 * Trait Verdict
 *
 * The verdict put on every answer: `block` is yes for a proxy or a VPN,
 * a risk over the block line, or a blocked country, and no again for an
 * allowed one.
 *
 * @since 1.0.0
 */
trait Verdict {

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
