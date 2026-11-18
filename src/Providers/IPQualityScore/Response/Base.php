<?php
/**
 * IPQualityScore response
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Providers\IPQualityScore\Response;

use SugarCommerce\IpLookup\Response;

/**
 * Class Base
 *
 * What every IPQualityScore answer carries: whether it worked, its request
 * id and any message.
 *
 * @since 1.0.0
 */
abstract class Base extends Response {

	/**
	 * Whether IPQualityScore says the request worked.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function is_success(): bool {
		return (bool) ( $this->data['success'] ?? false );
	}

	/**
	 * The request's id, for reporting it later.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_request_id(): ?string {
		return isset( $this->data['request_id'] ) ? (string) $this->data['request_id'] : null;
	}

	/**
	 * The message, if there is one.
	 *
	 * @since 1.0.0
	 *
	 * @return string|null
	 */
	public function get_message(): ?string {
		return isset( $this->data['message'] ) && is_scalar( $this->data['message'] ) ? (string) $this->data['message'] : null;
	}

	/**
	 * The errors, if there are any.
	 *
	 * @since 1.0.0
	 *
	 * @return array
	 */
	public function get_errors(): array {
		return (array) ( $this->data['errors'] ?? array() );
	}
}
