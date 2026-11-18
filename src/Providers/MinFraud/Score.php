<?php
/**
 * minFraud score
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Providers\MinFraud;

use SugarCommerce\IpLookup\Response;

/**
 * Class Score
 *
 * MaxMind minFraud Score's answer: how likely the transaction is to be
 * fraud, as a percentage from 0.01 to 99, and how risky the address is on
 * its own.
 *
 * @since 1.0.0
 */
class Score extends Response {

	/**
	 * The transaction's risk, 0.01 to 99.
	 *
	 * @since 1.0.0
	 *
	 * @return float
	 */
	public function get_risk_score(): float {
		return (float) ( $this->data['risk_score'] ?? 0 );
	}

	/**
	 * Whether the risk is at or above a threshold.
	 *
	 * @since 1.0.0
	 *
	 * @param float $threshold The lowest risk that counts. Default 75.
	 *
	 * @return bool
	 */
	public function is_high_risk( float $threshold = 75.0 ): bool {
		return $this->get_risk_score() >= $threshold;
	}

	/**
	 * The address's own risk, 0.01 to 99.
	 *
	 * @since 1.0.0
	 *
	 * @return float|null Null when no address was sent.
	 */
	public function get_ip_risk(): ?float {
		$risk = $this->data['ip_address']['risk'] ?? null;

		return is_numeric( $risk ) ? (float) $risk : null;
	}

	/**
	 * The query's id, to look it up in the MaxMind account or report it.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function get_query_id(): string {
		return (string) ( $this->data['id'] ?? '' );
	}

	/**
	 * The account's balance after this query, in US dollars.
	 *
	 * @since 1.0.0
	 *
	 * @return float
	 */
	public function get_funds_remaining(): float {
		return (float) ( $this->data['funds_remaining'] ?? 0 );
	}

	/**
	 * How many more queries the balance pays for.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	public function get_queries_remaining(): int {
		return (int) ( $this->data['queries_remaining'] ?? 0 );
	}

	/**
	 * What MaxMind did not like about the request: a field it ignored, an
	 * address it could not read.
	 *
	 * @since 1.0.0
	 *
	 * @return array
	 */
	public function get_warnings(): array {
		return (array) ( $this->data['warnings'] ?? array() );
	}
}
