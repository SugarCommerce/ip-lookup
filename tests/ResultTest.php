<?php
/**
 * Result tests.
 *
 * @package SugarCommerce\IpLookup
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\IpLookup\Models\Result;

/**
 * The common answer: what it keeps, how it cleans, and null as no answer.
 */
final class ResultTest extends TestCase {

	/**
	 * Nothing given is null for every answer, never false or zero.
	 *
	 * @return void
	 */
	public function test_nothing_said_is_null(): void {
		$result = new Result( 'test', '8.8.8.8' );

		foreach ( Result::fields() as $field ) {
			$this->assertNull( $result->to_array()[ $field ], $field );
		}

		$this->assertNull( $result->is_anonymous() );
		$this->assertNull( $result->is_suspicious() );
		$this->assertNull( $result->is_high_risk() );
		$this->assertSame( 'test', $result->get_provider() );
		$this->assertSame( '8.8.8.8', $result->get_ip() );
	}

	/**
	 * Each provider's way of writing an ASN comes out one way.
	 *
	 * @param mixed       $given    What the provider wrote.
	 * @param string|null $expected What the result says.
	 *
	 * @return void
	 */
	#[DataProvider( 'asns' )]
	public function test_asn_is_written_one_way( mixed $given, ?string $expected ): void {
		$this->assertSame( $expected, ( new Result( 't', '1.1.1.1', array( 'asn' => $given ) ) )->get_asn() );
	}

	/**
	 * @return array<string, array{mixed, string|null}>
	 */
	public static function asns(): array {
		return array(
			'prefixed'   => array( 'AS15169', 'AS15169' ),
			'lower'      => array( 'as13335', 'AS13335' ),
			'bare'       => array( '16509', 'AS16509' ),
			'number'     => array( 16509, 'AS16509' ),
			'nonsense'   => array( 'Google', null ),
			'empty'      => array( '', null ),
		);
	}

	/**
	 * Scores are held to 0-100 and rounded; codes are upper case; empty
	 * strings are no answer; connection types lose case and spaces.
	 *
	 * @return void
	 */
	public function test_values_are_cleaned(): void {
		$result = new Result(
			't',
			'1.1.1.1',
			array(
				'risk_score'      => 140.6,
				'country_code'    => 'gb',
				'continent_code'  => 'eu',
				'city'            => '  ',
				'connection_type' => 'Data Center',
				'is_vpn'          => 'yes',
				'is_proxy'        => 'no',
				'latitude'        => '51.5',
				'region'          => array( 'name' => 'England' ),
				'unknown_key'     => 'ignored',
			)
		);

		$this->assertSame( 100, $result->get_risk_score() );
		$this->assertSame( 'GB', $result->get_country_code() );
		$this->assertSame( 'EU', $result->get_continent_code() );
		$this->assertNull( $result->get_city() );
		$this->assertSame( 'datacenter', $result->get_connection_type() );
		$this->assertTrue( $result->is_vpn() );
		$this->assertFalse( $result->is_proxy() );
		$this->assertSame( 51.5, $result->get_latitude() );
		$this->assertNull( $result->get_region() );
		$this->assertArrayNotHasKey( 'unknown_key', $result->to_array() );
		$this->assertSame( 0, ( new Result( 't', 'x', array( 'risk_score' => -4 ) ) )->get_risk_score() );
	}

	/**
	 * Anonymous is true on any yes, false only when every answer is no, and
	 * null when nothing was said about any of them.
	 *
	 * @return void
	 */
	public function test_anonymous_reads_three_answers(): void {
		$this->assertTrue( ( new Result( 't', 'x', array( 'is_tor' => true ) ) )->is_anonymous() );
		$this->assertTrue( ( new Result( 't', 'x', array( 'is_proxy' => false, 'is_vpn' => true ) ) )->is_anonymous() );
		$this->assertFalse( ( new Result( 't', 'x', array( 'is_proxy' => false ) ) )->is_anonymous() );
		$this->assertFalse( ( new Result( 't', 'x', array( 'is_proxy' => false, 'is_vpn' => false, 'is_tor' => false ) ) )->is_anonymous() );
		$this->assertNull( ( new Result( 't', 'x', array( 'is_hosting' => false ) ) )->is_anonymous() );

		$this->assertTrue( ( new Result( 't', 'x', array( 'is_hosting' => true ) ) )->is_suspicious() );
		$this->assertFalse( ( new Result( 't', 'x', array( 'is_hosting' => false ) ) )->is_suspicious() );
		$this->assertNull( ( new Result( 't', 'x', array( 'is_relay' => true ) ) )->is_suspicious() );
	}

	/**
	 * The threshold is inclusive.
	 *
	 * @return void
	 */
	public function test_high_risk_threshold_is_inclusive(): void {
		$this->assertTrue( ( new Result( 't', 'x', array( 'risk_score' => 75 ) ) )->is_high_risk() );
		$this->assertFalse( ( new Result( 't', 'x', array( 'risk_score' => 74 ) ) )->is_high_risk() );
		$this->assertTrue( ( new Result( 't', 'x', array( 'risk_score' => 50 ) ) )->is_high_risk( 50 ) );
	}
}
