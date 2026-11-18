<?php
/**
 * IPQualityScore tests.
 *
 * @package SugarCommerce\IpLookup
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Tests\Providers;

use PHPUnit\Framework\TestCase;
use SugarCommerce\IpLookup\Providers\IPQualityScore;
use SugarCommerce\IpLookup\Tests\Support\FakeHttp;

/**
 * Each endpoint's URL, the refusals in a 200, and the common answer.
 */
final class IPQualityScoreTest extends TestCase {

	/**
	 * @return void
	 */
	protected function setUp(): void {
		ipl_reset();
	}

	/**
	 * An address check goes to ip/{key}/{ip} with the strictness and the
	 * visitor's agent and language.
	 *
	 * @return void
	 */
	public function test_check_ip(): void {
		$_SERVER['HTTP_USER_AGENT']      = 'Mozilla/5.0 <b>Test</b>';
		$_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'en-GB';
		FakeHttp::json(
			array(
				'success'         => true,
				'fraud_score'     => 88,
				'proxy'           => true,
				'vpn'             => true,
				'tor'             => false,
				'bot_status'      => true,
				'recent_abuse'    => true,
				'country_code'    => 'RO',
				'ASN'             => 9009,
				'ISP'             => 'M247',
				'connection_type' => 'Data Center',
				'request_id'      => 'req-1',
			)
		);

		$client = new IPQualityScore( 'secret', array( 'strictness' => 9 ) );
		$check  = $client->check_ip( '8.8.8.8' );

		$this->assertSame( 88.0, $check->get_fraud_score() );
		$this->assertTrue( $check->is_proxy() );
		$this->assertTrue( $check->is_vpn() );
		$this->assertSame( 'High Risk', $check->get_risk_level() );
		$this->assertSame( 'req-1', $check->get_request_id() );
		$this->assertTrue( $check->is_success() );
		$this->assertSame( 3, $client->get_strictness() );

		$url = FakeHttp::last()['url'];
		$this->assertStringStartsWith( 'https://ipqualityscore.com/api/json/ip/secret/8.8.8.8?', $url );
		$this->assertStringContainsString( 'strictness=3', $url );
		$this->assertStringContainsString( 'user_agent=Mozilla%2F5.0+Test', $url );
		$this->assertStringContainsString( 'user_language=en-GB', $url );
	}

	/**
	 * IPQualityScore refuses with a 200 and `success: false`: an error, and
	 * not cached as an answer.
	 *
	 * @return void
	 */
	public function test_refusal_in_a_200(): void {
		FakeHttp::json( array( 'success' => false, 'message' => 'Invalid or unauthorized key.' ) );
		FakeHttp::json( array( 'success' => true, 'fraud_score' => 1 ) );
		$client = new IPQualityScore( 'bad', array( 'failure_ttl' => 0 ) );

		$error = $client->check_ip( '8.8.8.8' );

		$this->assertSame( 'ipqualityscore_api_error', $error->get_error_code() );
		$this->assertSame( 'Invalid or unauthorized key.', $error->get_error_message() );
		$this->assertSame( 1.0, $client->check_ip( '8.8.8.8' )->get_fraud_score() );
	}

	/**
	 * An `errors` list is an error.
	 *
	 * @return void
	 */
	public function test_errors_list(): void {
		FakeHttp::json( array( 'errors' => array( 'Too many', 'requests' ) ) );

		$this->assertSame( 'Too many requests', ( new IPQualityScore( 'k' ) )->check_ip( '8.8.8.8' )->get_error_message() );
	}

	/**
	 * An email check validates first and goes to its endpoint.
	 *
	 * @return void
	 */
	public function test_validate_email(): void {
		FakeHttp::json( array( 'success' => true, 'valid' => true, 'disposable' => true, 'leaked' => false ) );
		$client = new IPQualityScore( 'k' );

		$email = $client->validate_email( 'a@example.com' );
		$this->assertTrue( $email->is_disposable() );
		$this->assertSame( 'https://ipqualityscore.com/api/json/email/k', FakeHttp::last()['url'] );
		$this->assertSame( 'a@example.com', FakeHttp::last()['args']['body']['email'] );


		$this->assertSame( 'ipqualityscore_invalid_email', $client->validate_email( 'nope' )->get_error_code() );
		$this->assertSame( 1, FakeHttp::count() );
	}

	/**
	 * The common answer.
	 *
	 * @return void
	 */
	public function test_lookup(): void {
		FakeHttp::json(
			array(
				'success'         => true,
				'fraud_score'     => 90,
				'proxy'           => true,
				'vpn'             => false,
				'tor'             => true,
				'bot_status'      => false,
				'recent_abuse'    => false,
				'country_code'    => 'NL',
				'region'          => 'North Holland',
				'city'            => 'Amsterdam',
				'ASN'             => 60781,
				'ISP'             => 'LeaseWeb',
				'organization'    => 'LeaseWeb Netherlands',
				'connection_type' => 'Data Center',
				'latitude'        => 52.37,
				'longitude'       => 4.89,
				'timezone'        => 'Europe/Amsterdam',
			)
		);

		$result = ( new IPQualityScore( 'k' ) )->lookup( '8.8.8.8' );

		$this->assertSame( 90, $result->get_risk_score() );
		$this->assertTrue( $result->is_anonymous() );
		$this->assertTrue( $result->is_tor() );
		$this->assertFalse( $result->is_bot() );
		$this->assertTrue( $result->is_hosting() );
		$this->assertSame( 'AS60781', $result->get_asn() );
		$this->assertSame( 'datacenter', $result->get_connection_type() );
		$this->assertSame( 'LeaseWeb Netherlands', $result->get_organisation() );
		$this->assertSame( 'Europe/Amsterdam', $result->get_timezone() );
	}
}
