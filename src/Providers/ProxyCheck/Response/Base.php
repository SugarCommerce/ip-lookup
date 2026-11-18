<?php
/**
 * ProxyCheck response
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Providers\ProxyCheck\Response;

use SugarCommerce\Network\Remote\Response;

/**
 * Class Base
 *
 * A ProxyCheck answer. The API keys its answer by what was asked -- the
 * address or the email -- beside `status`, `node` and `query time`, so the
 * first other key is the one this response is about.
 *
 * @since 1.0.0
 */
abstract class Base extends Response {

	/**
	 * The identifier (IP or email) being checked
	 *
	 * @var string
	 */
	protected string $identifier;

	/**
	 * Block status constants
	 */
	protected const BLOCK_YES = 'yes';
	protected const BLOCK_NO = 'no';
	protected const BLOCK_NA = 'na';


	/**
	 * Initialize the response object
	 *
	 * @param array $data Raw response data from ProxyCheck API
	 */
	public function __construct( array $data ) {
		parent::__construct( $data );

		$this->identifier = (string) array_key_first(
			array_diff_key(
				$data,
				array(
					'status'        => 1,
					'message'       => 1,
					'node'          => 1,
					'query time'    => 1,
					'block'         => 1,
					'block_reason'  => 1,
					'block_details' => 1,
				)
			)
		);
	}

	/**
	 * Get node information
	 *
	 * @return string|null
	 */
	public function get_node(): ?string {
		return $this->data['node'] ?? null;
	}

	/**
	 * Get query time
	 *
	 * @return float|null
	 */
	public function get_query_time(): ?float {
		if ( ! isset( $this->data['query time'] ) ) {
			return null;
		}

		return (float) str_replace( 's', '', $this->data['query time'] );
	}

	/**
	 * Get status message if present
	 *
	 * @return string|null
	 */
	public function get_status(): ?string {
		return $this->data['status'] ?? null;
	}

	/**
	 * Get error message if present
	 *
	 * @return string|null
	 */
	public function get_message(): ?string {
		return $this->data['message'] ?? null;
	}

	/**
	 * Check if the query was successful
	 *
	 * @return bool
	 */
	public function is_successful(): bool {
		return ( $this->data['status'] ?? 'ok' ) === 'ok';
	}

	/**
	 * Get block status
	 *
	 * @return bool True if IP/email should be blocked
	 */
	public function should_block(): bool {
		return ( $this->data['block'] ?? self::BLOCK_NO ) === self::BLOCK_YES;
	}

	/**
	 * Get reason for blocking if blocked
	 *
	 * @return string|null Block reason or null if not blocked
	 */
	public function get_block_reason(): ?string {
		return $this->data['block_reason'] ?? null;
	}

	/**
	 * Get detailed block information
	 *
	 * @return array|null Array of block details or null if not available
	 */
	public function get_block_details(): ?array {
		return $this->data['block_details'] ?? null;
	}
}
