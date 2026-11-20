<?php
/**
 * Security tests: what a provider's answer or a caller's input must not
 * be able to do.
 *
 * @package SugarCommerce\IpLookup
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\IpLookup\Providers\IPQualityScore;
use SugarCommerce\IpLookup\Providers\ProxyCheck;
use SugarCommerce\IpLookup\Result;
use SugarCommerce\IpLookup\Tests\Support\FakeHttp;

/**
 * An answer is read as untrusted data.
 */
final class SecurityTest extends TestCase {

	/**
	 * @return void
	 */
	protected function setUp(): void {
		ipl_reset();
	}

	/**
	 * A field of the wrong type is no answer, not a fatal error on the
	 * checkout that asked.
	 *
	 * @return void
	 */
	public function test_proxycheck_field_of_the_wrong_type_is_no_answer(): void {
		FakeHttp::json(
			array(
				'status'     => 'ok',
				'query time' => array( '0.1s' ),
				'8.8.8.8'    => array(
					'proxy'        => 'yes',
					'type'         => array( 'VPN' ),
					'asn'          => 9009,
					'provider'     => array( 'M247' ),
					'organisation' => true,
					'city'         => 12345,
					'country'      => array( 'Sweden' ),
					'timezone'     => array(),
					'risk'         => 'high',
					'devices'      => 'many',
					'operator'     => 'Mullvad',
				),
			)
		);

		$client = new ProxyCheck( 'key' );
		$result = $client->lookup( '8.8.8.8' );

		$this->assertInstanceOf( Result::class, $result );
		$this->assertTrue( $result->is_proxy() );
		$this->assertNull( $result->get_risk_score() );
		$this->assertSame( 'AS9009', $result->get_asn() );
		$this->assertSame( '12345', $result->get_city() );
		$this->assertNull( $result->get_isp() );

		$check = $result->get_response();

		$this->assertNull( $check->get_type() );
		$this->assertNull( $check->get_provider() );
		$this->assertSame( '9009', $check->get_asn() );
		$this->assertNull( $check->get_query_time() );
		$this->assertNull( $check->get_devices() );
		$this->assertNull( $check->get_country() );
		$this->assertNull( $check->get_operator_details() );
		$this->assertSame( '(9009)', $check->get_formatted_operator() );
		$this->assertSame( '12345', $check->get_formatted_address() );
		$this->assertTrue( $check->should_block() );
	}

	/**
	 * The same for IPQualityScore.
	 *
	 * @return void
	 */
	public function test_ipqualityscore_field_of_the_wrong_type_is_no_answer(): void {
		FakeHttp::json(
			array(
				'success'         => true,
				'fraud_score'     => array( 99 ),
				'country_code'    => 44,
				'connection_type' => array( 'Data Center' ),
				'ISP'             => array(),
				'host'            => false,
				'transaction_details' => 'none',
			)
		);

		$client = new IPQualityScore( 'secret' );
		$result = $client->lookup( '8.8.8.8' );

		$this->assertInstanceOf( Result::class, $result );
		$this->assertNull( $result->get_risk_score() );
		$this->assertNull( $result->get_connection_type() );
		$this->assertSame( '44', $result->get_country_code() );

		$check = $client->check_ip( '8.8.8.8' );

		$this->assertNull( $check->get_isp() );
		$this->assertNull( $check->get_host() );
		$this->assertNull( $check->get_transaction_details() );
		$this->assertSame( 'Unknown', $check->get_risk_level() );
	}
}
