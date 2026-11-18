<?php
/**
 * IPinfo domains
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Providers\IPInfo;

use SugarCommerce\Network\Remote\Response;

/**
 * Class Domains
 *
 * Domains hosted on the address. Premium plan.
 *
 * @since 1.0.0
 */
class Domains extends Response {

	/**
	 * How many domains there are.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	public function get_total(): int {
		return (int) ( $this->data['total'] ?? 0 );
	}

	/**
	 * This page of them.
	 *
	 * @since 1.0.0
	 *
	 * @return array
	 */
	public function get_domains(): array {
		return (array) ( $this->data['domains'] ?? array() );
	}

	/**
	 * Which page this is.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	public function get_page(): int {
		return (int) ( $this->data['page'] ?? 0 );
	}
}
