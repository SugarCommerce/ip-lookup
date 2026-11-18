<?php
/**
 * IPinfo abuse
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
 * Class Abuse
 *
 * Who to tell about abuse from the address. Business plan and above.
 *
 * @since 1.0.0
 */
class Abuse extends Response {

	/**
	 * The abuse contact's postal address.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_address(): ?string {
		$value = $this->data['address'] ?? null;

		return is_scalar( $value ) && '' !== (string) $value ? (string) $value : null;
	}

	/**
	 * The abuse contact's country code.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_country(): ?string {
		$value = $this->data['country'] ?? null;

		return is_scalar( $value ) && '' !== (string) $value ? (string) $value : null;
	}

	/**
	 * The abuse contact's email address.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_email(): ?string {
		$value = $this->data['email'] ?? null;

		return is_scalar( $value ) && '' !== (string) $value ? (string) $value : null;
	}

	/**
	 * The abuse contact's name.
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
	 * The network the contact covers.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_network(): ?string {
		$value = $this->data['network'] ?? null;

		return is_scalar( $value ) && '' !== (string) $value ? (string) $value : null;
	}

	/**
	 * The abuse contact's phone number.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_phone(): ?string {
		$value = $this->data['phone'] ?? null;

		return is_scalar( $value ) && '' !== (string) $value ? (string) $value : null;
	}
}
