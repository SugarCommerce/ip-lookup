<?php
/**
 * minFraud tests.
 *
 * @package SugarCommerce\IpLookup
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Tests\Providers;

use PHPUnit\Framework\TestCase;
use SugarCommerce\IpLookup\Providers\MinFraud;
use SugarCommerce\IpLookup\Providers\MinFraud\Score;
use SugarCommerce\IpLookup\Tests\Support\FakeHttp;

/**
 * Score, its errors, and the address on its own.
 */
final class MinFraudTest extends TestCase {

	/**
	 * @return void
	 */
	protected function setUp(): void {
		ipl_reset();
	}

	/**
	 * A score, read by name, sent with basic authentication.
	 *
	 * @return void
	 */
	public function test_score(): void {
		FakeHttp::json(
			array(
				'id'                => 'abc-123',
				'risk_score'        => 12.5,
				'funds_remaining'   => 42,
				'queries_remaining' => 1000,
				'ip_address'        => array( 'risk' => 4.2 ),
				'warnings'          => array( array( 'code' => 'BILLING_POSTAL_NOT_FOUND' ) ),
			)
		);

		$score = ( new MinFraud( 'acct', 'licence' ) )->check_score( array( 'device' => array( 'ip_address' => '8.8.8.8' ) ) );

		$this->assertInstanceOf( Score::class, $score );
		$this->assertSame( 12.5, $score->get_risk_score() );
		$this->assertFalse( $score->is_high_risk() );
		$this->assertTrue( $score->is_high_risk( 12.5 ) );
		$this->assertSame( 4.2, $score->get_ip_risk() );
		$this->assertSame( 'abc-123', $score->get_query_id() );
		$this->assertSame( 42.0, $score->get_funds_remaining() );
		$this->assertSame( 1000, $score->get_queries_remaining() );
		$this->assertCount( 1, $score->get_warnings() );

		$request = FakeHttp::last();
		$this->assertSame( 'POST', $request['method'] );
		$this->assertSame( 'Basic ' . base64_encode( 'acct:licence' ), $request['args']['headers']['Authorization'] );
		$this->assertSame( '{"device":{"ip_address":"8.8.8.8"}}', $request['args']['body'] );
	}

	/**
	 * Without both credentials nothing is sent.
	 *
	 * @return void
	 */
	public function test_missing_credentials(): void {
		foreach ( array( array( '', 'k' ), array( 'a', '' ) ) as $pair ) {
			$this->assertSame( 'minfraud_missing_credentials', ( new MinFraud( $pair[0], $pair[1] ) )->check_score( array() )->get_error_code() );
		}

		$this->assertSame( 0, FakeHttp::count() );
	}

	/**
	 * An error body is an error, never a score of 0.
	 *
	 * @return void
	 */
	public function test_error_is_not_a_zero_score(): void {
		FakeHttp::json(
			array(
				'code'  => 'INSUFFICIENT_FUNDS',
				'error' => 'out of funds',
			),
			402
		);

		$error = ( new MinFraud( 'a', 'k' ) )->check_score( array( 'device' => array( 'ip_address' => '8.8.8.8' ) ) );

		$this->assertSame( 'minfraud_api_error', $error->get_error_code() );
		$this->assertSame( 'out of funds', $error->get_error_message() );
		$this->assertSame( 'INSUFFICIENT_FUNDS', $error->get_error_data()['code'] );

		// An error code with a 200 is still an error.
		FakeHttp::json( array( 'code' => 'IP_ADDRESS_RESERVED', 'error' => 'reserved' ) );
		$this->assertSame( 'minfraud_api_error', ( new MinFraud( 'a', 'k' ) )->check_score( array( 'x' => 1 ) )->get_error_code() );
	}

	/**
	 * The same payload in another key order is the same question.
	 *
	 * @return void
	 */
	public function test_key_order_shares_a_cache_entry(): void {
		FakeHttp::json( array( 'risk_score' => 1 ) );
		$client = new MinFraud( 'a', 'k' );

		$client->check_score( array( 'email' => array( 'address' => 'a@example.com' ), 'device' => array( 'ip_address' => '8.8.8.8', 'user_agent' => 'x' ) ) );
		$client->check_score( array( 'device' => array( 'user_agent' => 'x', 'ip_address' => '8.8.8.8' ), 'email' => array( 'address' => 'a@example.com' ) ) );

		$this->assertSame( 1, FakeHttp::count() );
	}

	/**
	 * The common answer is the address's own risk, falling back to the
	 * whole score.
	 *
	 * @return void
	 */
	public function test_lookup(): void {
		FakeHttp::json( array( 'risk_score' => 30, 'ip_address' => array( 'risk' => 61.7 ) ) );
		FakeHttp::json( array( 'risk_score' => 9 ) );

		$this->assertSame( 62, ( new MinFraud( 'a', 'k' ) )->lookup( '8.8.8.8' )->get_risk_score() );
		$this->assertSame( 9, ( new MinFraud( 'a', 'k' ) )->lookup( '1.1.1.1' )->get_risk_score() );
		$this->assertSame( 'minfraud_invalid_ip', ( new MinFraud( 'a', 'k' ) )->lookup( '10.0.0.1' )->get_error_code() );
	}
}
