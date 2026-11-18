<?php
/**
 * Provider
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup;

use WP_Error;

/**
 * Interface Provider
 *
 * A service that can say something about an IP address. Each one answers
 * in its own shape and with its own idea of a score; lookup() brings that
 * down to one Result, so a rule or a fraud check can be written once and
 * the service behind it changed later.
 *
 * @since 1.0.0
 */
interface Provider {

	/**
	 * The provider's id, as conditions and cache keys know it.
	 *
	 * @since 1.0.0
	 *
	 * @return string e.g. `proxycheck`.
	 */
	public function get_id(): string;

	/**
	 * The provider's name, for people.
	 *
	 * @since 1.0.0
	 *
	 * @return string e.g. `ProxyCheck`.
	 */
	public function get_name(): string;

	/**
	 * Ask about one address.
	 *
	 * An address that is not on the public internet -- a private range,
	 * loopback, a documentation block -- is refused before any request, so
	 * a local test or a misread proxy header costs no quota.
	 *
	 * @since 1.0.0
	 *
	 * @param string $ip The address.
	 *
	 * @return Result|WP_Error
	 */
	public function lookup( string $ip ): Result|WP_Error;
}
