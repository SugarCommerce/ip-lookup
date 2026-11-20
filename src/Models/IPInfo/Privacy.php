<?php
/**
 * IPinfo privacy
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
 * Class Privacy
 *
 * Whether the address hides who is behind it. Business plan and above.
 *
 * @since 1.0.0
 */
class Privacy extends Response {

	/**
	 * Whether it is a VPN exit.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function is_vpn(): bool {
		return (bool) ( $this->data['vpn'] ?? false );
	}

	/**
	 * Whether it is a proxy.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function is_proxy(): bool {
		return (bool) ( $this->data['proxy'] ?? false );
	}

	/**
	 * Whether it is a Tor exit node.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function is_tor(): bool {
		return (bool) ( $this->data['tor'] ?? false );
	}

	/**
	 * Whether it is a privacy relay, such as iCloud Private Relay.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function is_relay(): bool {
		return (bool) ( $this->data['relay'] ?? false );
	}

	/**
	 * Whether it belongs to a hosting company or a data centre.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function is_hosting(): bool {
		return (bool) ( $this->data['hosting'] ?? false );
	}

	/**
	 * The VPN or relay service's name, when known.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_service(): ?string {
		$value = $this->data['service'] ?? null;

		return is_scalar( $value ) && '' !== (string) $value ? (string) $value : null;
	}
}
