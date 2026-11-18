<?php
/**
 * IPinfo asn
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Providers\IPInfo;

use SugarCommerce\IpLookup\Response;

/**
 * Class ASN
 *
 * The network the address belongs to. Basic plan and above.
 *
 * @since 1.0.0
 */
class ASN extends Response {

	/**
	 * The ASN, written `AS15169`.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_asn(): ?string {
		$value = $this->data['asn'] ?? null;

		return is_scalar( $value ) && '' !== (string) $value ? (string) $value : null;
	}

	/**
	 * The network's name.
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
	 * The network's domain.
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
	 * The announced route, e.g. `8.8.8.0/24`.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_route(): ?string {
		$value = $this->data['route'] ?? null;

		return is_scalar( $value ) && '' !== (string) $value ? (string) $value : null;
	}

	/**
	 * The network's kind: `isp`, `hosting`, `business` or `education`.
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
