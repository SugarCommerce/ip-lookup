<?php
/**
 * Lookup
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
 * Class Lookup
 *
 * Several providers asked as one: the first that answers, or all of them.
 *
 * Each answer is kept for the rest of the request, failures included, so a
 * page that asks five times -- five conditions on one rule, say -- spends
 * one call, and an outage costs one timeout rather than five.
 *
 * @since 1.0.0
 */
final class Lookup {

	/**
	 * The providers, in the order they are asked.
	 *
	 * @var Provider[]
	 */
	private array $providers;

	/**
	 * Answers already given in this request, by provider and address.
	 *
	 * @var array<string, Result|WP_Error>
	 */
	private array $answers = array();

	/**
	 * Ask these providers.
	 *
	 * @since 1.0.0
	 *
	 * @param Provider ...$providers In the order to ask them.
	 */
	public function __construct( Provider ...$providers ) {
		$this->providers = $providers;
	}

	/**
	 * The providers, in order.
	 *
	 * @since 1.0.0
	 *
	 * @return Provider[]
	 */
	public function get_providers(): array {
		return $this->providers;
	}

	/**
	 * One provider's answer.
	 *
	 * @since 1.0.0
	 *
	 * @param Provider $provider The provider.
	 * @param string   $ip       The address.
	 *
	 * @return Result|WP_Error
	 */
	public function ask( Provider $provider, string $ip ): Result|WP_Error {
		$ip  = trim( $ip );
		$key = spl_object_id( $provider ) . '|' . $ip;

		return $this->answers[ $key ] ??= $provider->lookup( $ip );
	}

	/**
	 * The first provider that answers.
	 *
	 * The next is asked only when one fails, so a second service is a
	 * fallback for an outage, not a second bill.
	 *
	 * @since 1.0.0
	 *
	 * @param string $ip The address.
	 *
	 * @return Result|WP_Error The last failure when none answered.
	 */
	public function first( string $ip ): Result|WP_Error {
		$error = new WP_Error( 'iplookup_no_provider', __( 'No IP lookup service is set up.', 'sugarcommerce' ) );

		foreach ( $this->providers as $provider ) {
			$answer = $this->ask( $provider, $ip );

			if ( ! is_wp_error( $answer ) ) {
				return $answer;
			}

			$error = $answer;
		}

		return $error;
	}

	/**
	 * Every provider's answer.
	 *
	 * Different services disagree on the long tail; asking two and acting
	 * when both agree is how precision is bought.
	 *
	 * @since 1.0.0
	 *
	 * @param string $ip The address.
	 *
	 * @return array<string, Result|WP_Error> Keyed by provider id.
	 */
	public function all( string $ip ): array {
		$answers = array();

		foreach ( $this->providers as $provider ) {
			$answers[ $provider->get_id() ] = $this->ask( $provider, $ip );
		}

		return $answers;
	}

	/**
	 * Forget the answers kept for this request.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public function reset(): void {
		$this->answers = array();
	}
}
