<?php
/**
 * ProxyCheck dashboard response
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Providers\ProxyCheck\Response\Dashboard;

use SugarCommerce\IpLookup\Response;

/**
 * Abstract class BaseResponse
 *
 * Base response handler for ProxyCheck.io API responses.
 */
abstract class Base extends Response {

	/**
	 * Format the response data for consistent output
	 *
	 * @return array
	 */
	abstract public function format(): array;

	/**
	 * Get response status if available
	 *
	 * @return string|null
	 */
	public function get_status(): ?string {
		return $this->data['status'] ?? null;
	}

	/**
	 * Get response message if available
	 *
	 * @return string|null
	 */
	public function get_message(): ?string {
		return $this->data['message'] ?? null;
	}

	/**
	 * Check if the response indicates success
	 *
	 * @return bool
	 */
	public function is_successful(): bool {
		return ( $this->get_status() === 'ok' );
	}

	/**
	 * Safely get integer value from data
	 *
	 * @param string $key     The key to retrieve
	 * @param int    $default_value Default value if not found
	 *
	 * @return int
	 */
	protected function get_int( string $key, int $default_value = 0 ): int {
		return (int) ( $this->data[ $key ] ?? $default_value );
	}

	/**
	 * Safely get nested integer value from data
	 *
	 * @param string $parent_key  Parent key
	 * @param string $key     The key to retrieve
	 * @param int    $default_value Default value if not found
	 *
	 * @return int
	 */
	protected function get_nested_int( string $parent_key, string $key, int $default_value = 0 ): int {
		return (int) ( $this->data[ $parent_key ][ $key ] ?? $default_value );
	}

	/**
	 * Safely get string value from data
	 *
	 * @param string $key     The key to retrieve
	 * @param string $default_value Default value if not found
	 *
	 * @return string
	 */
	protected function get_string( string $key, string $default_value = '' ): string {
		return (string) ( $this->data[ $key ] ?? $default_value );
	}

	/**
	 * Safely get array value from data
	 *
	 * @param string $key     The key to retrieve
	 * @param array  $default_value Default value if not found
	 *
	 * @return array
	 */
	protected function get_array( string $key, array $default_value = [] ): array {
		return is_array( $this->data[ $key ] ?? null ) ? $this->data[ $key ] : $default_value;
	}
}
