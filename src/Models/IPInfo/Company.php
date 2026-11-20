<?php
/**
 * IPinfo company
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Models\IPInfo;

use SugarCommerce\Network\Models\Remote\Response;

/**
 * Class Company
 *
 * The company the address is registered to. Business plan and above.
 *
 * @since 1.0.0
 */
class Company extends Response {

	/**
	 * The company's name.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_name(): ?string {
		$value = $this->data['name'] ?? null;

		return is_scalar( $value ) && '' !== (string) $value ? (string) $value : null;
	}

	/**
	 * The company's domain.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_domain(): ?string {
		$value = $this->data['domain'] ?? null;

		return is_scalar( $value ) && '' !== (string) $value ? (string) $value : null;
	}

	/**
	 * The company's kind: `isp`, `hosting`, `business` or `education`.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_type(): ?string {
		$value = $this->data['type'] ?? null;

		return is_scalar( $value ) && '' !== (string) $value ? (string) $value : null;
	}
}
