<?php
/**
 * ProxyCheck email response
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Providers\ProxyCheck\Response;

/**
 * Class DisposableEmailResponse
 *
 * Handles response data from the ProxyCheck.io API for disposable email checks.
 */
class DisposableEmail extends Base {

	/**
	 * Get the email address that was checked
	 *
	 * @return string|null
	 */
	public function get_email(): ?string {
		return $this->identifier ?? null;
	}

	/**
	 * Check if the email is from a disposable service
	 *
	 * @return bool
	 */
	public function is_disposable(): bool {
		return ( $this->data[ $this->identifier ]['disposable'] ?? null ) === 'yes';
	}
}
