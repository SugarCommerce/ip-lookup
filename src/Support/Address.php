<?php
/**
 * Address
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Support;

use SugarCommerce\Network\IP;
use SugarCommerce\Network\Remote\Service;

/**
 * Class Address
 *
 * An address as every provider is asked about it: public, and in its one
 * standard spelling.
 *
 * `2001:4860:4860:0:0:0:0:8888` and `2001:4860:4860::8888` are one
 * address, and a service answers about it under one of them. Asked in the
 * other, ProxyCheck's verdict was read from an entry that was not there
 * -- no proxy, no block -- and each spelling cost its own request and its
 * own cache entry. `::ffff:203.0.113.9`, an IPv4 visitor on a server
 * listening on both families, is asked about as the IPv4 address it is.
 *
 * @since 1.0.0
 */
final class Address {

	/**
	 * The address to ask about, or null when it is not worth asking.
	 *
	 * @since 1.0.0
	 *
	 * @param string $ip The address, in any spelling.
	 *
	 * @return string|null The standard spelling, or null for anything that
	 *                     is not a public address.
	 */
	public static function canonical( string $ip ): ?string {
		$canonical = IP::canonical( $ip );

		return null !== $canonical && Service::is_lookupable( $canonical ) ? $canonical : null;
	}

	/**
	 * The addresses to ask about: each once, in its standard spelling,
	 * leaving out those not worth asking.
	 *
	 * @since 1.0.0
	 *
	 * @param array $ips The addresses.
	 *
	 * @return string[]
	 */
	public static function canonical_list( array $ips ): array {
		$list = array();

		foreach ( $ips as $ip ) {
			$canonical = is_string( $ip ) ? self::canonical( $ip ) : null;

			if ( null !== $canonical ) {
				$list[ $canonical ] = $canonical;
			}
		}

		return array_values( $list );
	}
}
