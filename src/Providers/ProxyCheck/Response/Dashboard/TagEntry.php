<?php
/**
 * ProxyCheck tags export
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Providers\ProxyCheck\Response\Dashboard;

class TagEntry extends Base {

	/**
	 * Format tags data
	 *
	 * @return array Formatted tags data
	 */
	public function format(): array {
		return array_map( function ( $data ) {
			return [
				'total'     => (int) ( $data['types']['total'] ?? 0 ),
				'proxy'     => (int) ( $data['types']['proxy'] ?? 0 ),
				'vpn'       => (int) ( $data['types']['vpn'] ?? 0 ),
				'rule'      => (int) ( $data['types']['rule'] ?? 0 ),
				'addresses' => $data['addresses'] ?? [],
			];
		}, $this->data );
	}

	/**
	 * Get total entries count
	 *
	 * @return int
	 */
	public function get_count(): int {
		return count( $this->data );
	}

	/**
	 * Get all addresses across all tags
	 *
	 * @return array
	 */
	public function get_all_addresses(): array {
		$addresses = [];
		foreach ( $this->data as $tag ) {
			if ( isset( $tag['addresses'] ) && is_array( $tag['addresses'] ) ) {
				$addresses = array_merge( $addresses, $tag['addresses'] );
			}
		}

		return array_unique( $addresses );
	}
}
