<?php
/**
 * ProxyCheck address answer, on a map
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Traits\ProxyCheckIP;

/**
 * Trait MapLinks
 *
 * Links to the address's coordinates on Google Maps, Apple Maps, Bing
 * and OpenStreetMap.
 *
 * @since 1.0.0
 */
trait MapLinks {

	/**
	 * Base URLs for various mapping services
	 */
	private const MAP_URLS = [
		'google' => 'https://www.google.com/maps/search/?api=1&query=',
		'apple'  => 'https://maps.apple.com/?q=',
		'bing'   => 'https://www.bing.com/maps?cp=',
		'osm'    => 'https://www.openstreetmap.org/?mlat=',
	];

	/**
	 * Get Google Maps URL for the coordinates
	 *
	 * @return string|null URL to view location on Google Maps
	 */
	public function get_google_maps_url(): ?string {
		$coordinates = $this->get_coordinates();
		if ( ! $coordinates ) {
			return null;
		}

		return self::MAP_URLS['google'] .
				esc_attr( $coordinates['latitude'] ) . ',' .
				esc_attr( $coordinates['longitude'] );
	}

	/**
	 * Get Apple Maps URL for the coordinates
	 *
	 * @return string|null URL to view location on Apple Maps
	 */
	public function get_apple_maps_url(): ?string {
		$coordinates = $this->get_coordinates();
		if ( ! $coordinates ) {
			return null;
		}

		return self::MAP_URLS['apple'] .
				esc_attr( $coordinates['latitude'] ) . ',' .
				esc_attr( $coordinates['longitude'] );
	}

	/**
	 * Get Bing Maps URL for the coordinates
	 *
	 * @return string|null URL to view location on Bing Maps
	 */
	public function get_bing_maps_url(): ?string {
		$coordinates = $this->get_coordinates();
		if ( ! $coordinates ) {
			return null;
		}

		return self::MAP_URLS['bing'] .
				esc_attr( $coordinates['latitude'] ) . '~' .
				esc_attr( $coordinates['longitude'] );
	}

	/**
	 * Get OpenStreetMap URL for the coordinates
	 *
	 * @return string|null URL to view location on OpenStreetMap
	 */
	public function get_openstreetmap_url(): ?string {
		$coordinates = $this->get_coordinates();
		if ( ! $coordinates ) {
			return null;
		}

		return self::MAP_URLS['osm'] .
				esc_attr( $coordinates['latitude'] ) .
				'&mlon=' . esc_attr( $coordinates['longitude'] ) .
				'&zoom=12';
	}

	/**
	 * Get all map URLs for the coordinates
	 *
	 * @return array Array of map service URLs
	 */
	public function get_map_urls(): array {
		return [
			'google' => $this->get_google_maps_url(),
			'apple'  => $this->get_apple_maps_url(),
			'bing'   => $this->get_bing_maps_url(),
			'osm'    => $this->get_openstreetmap_url(),
		];
	}
}
