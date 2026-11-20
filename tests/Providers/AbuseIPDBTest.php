<?php
/**
 * AbuseIPDB tests.
 *
 * @package SugarCommerce\IpLookup
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Tests\Providers;

use PHPUnit\Framework\TestCase;
use SugarCommerce\IpLookup\Models\Result;
use SugarCommerce\IpLookup\Providers\AbuseIPDB;
use SugarCommerce\IpLookup\Tests\Support\FakeHttp;

/**
 * The Check endpoint, its errors, and the common answer.
 */
final class AbuseIPDBTest extends TestCase {

	/**
	 * @return void
	 */
	protected function setUp(): void {
		ipl_reset();
	}

	/**
	 * A full answer, read by name.
	 *
	 * @return void
	 */
	public function test_check_reads_the_answer(): void {
		FakeHttp::json(
			array(
				'data' => array(
					'abuseConfidenceScore' => 88,
					'totalReports'         => 14,
					'numDistinctUsers'     => 6,
					'countryCode'          => 'nl',
					'usageType'            => 'Data Center/Web Hosting/Transit',
					'isWhitelisted'        => false,
					'isTor'                => true,
					'isp'                  => 'Example Hosting',
					'lastReportedAt'       => gmdate( 'c', time() - 3 * DAY_IN_SECONDS - 60 ),
				),
			)
		);

		$check = ( new AbuseIPDB( 'key' ) )->check_ip( ' 8.8.8.8 ' );

		$this->assertSame( 88, $check->get_confidence_score() );
		$this->assertTrue( $check->is_abusive() );
		$this->assertFalse( $check->is_abusive( 89 ) );
		$this->assertSame( 14, $check->get_total_reports() );
		$this->assertSame( 6, $check->get_distinct_reporters() );
		$this->assertSame( 'NL', $check->get_country_code() );
		$this->assertTrue( $check->is_tor() );
		$this->assertFalse( $check->is_whitelisted() );
		$this->assertSame( 3, $check->get_last_reported_days() );
		$this->assertSame( 'Example Hosting', $check->get( 'isp' ) );

		$request = FakeHttp::last();
		$this->assertSame( 'key', $request['args']['headers']['Key'] );
		$this->assertStringContainsString( 'ipAddress=8.8.8.8', $request['url'] );
		$this->assertStringContainsString( 'maxAgeInDays=90', $request['url'] );
	}

	/**
	 * Never reported is no number of days, not zero.
	 *
	 * @return void
	 */
	public function test_never_reported_has_no_days(): void {
		FakeHttp::json( array( 'data' => array( 'lastReportedAt' => null ) ) );

		$this->assertNull( ( new AbuseIPDB( 'key' ) )->check_ip( '8.8.8.8' )->get_last_reported_days() );
	}

	/**
	 * No key fails before any request.
	 *
	 * @return void
	 */
	public function test_missing_key(): void {
		$this->assertSame( 'abuseipdb_missing_key', ( new AbuseIPDB() )->check_ip( '8.8.8.8' )->get_error_code() );
		$this->assertSame( 0, FakeHttp::count() );
	}

	/**
	 * The API's error list becomes the error, and is not cached as an answer.
	 *
	 * @return void
	 */
	public function test_api_error(): void {
		FakeHttp::json( array( 'errors' => array( array( 'detail' => 'Daily rate limit of 1000 requests exceeded.' ) ) ), 429 );

		$error = ( new AbuseIPDB( 'key' ) )->check_ip( '8.8.8.8' );

		$this->assertSame( 'abuseipdb_api_error', $error->get_error_code() );
		$this->assertSame( 'Daily rate limit of 1000 requests exceeded.', $error->get_error_message() );
		$this->assertSame( 429, $error->get_error_data()['status'] );
	}

	/**
	 * A body that is not JSON is an error with the body kept.
	 *
	 * @return void
	 */
	public function test_unreadable_answer(): void {
		FakeHttp::raw( '<html>Bad gateway</html>', 502 );

		$error = ( new AbuseIPDB( 'key' ) )->check_ip( '8.8.8.8' );

		$this->assertSame( 'abuseipdb_bad_response', $error->get_error_code() );
		$this->assertSame( '<html>Bad gateway</html>', $error->get_error_data()['body'] );
	}

	/**
	 * Two windows ask different questions and keep different answers.
	 *
	 * @return void
	 */
	public function test_window_is_part_of_the_question(): void {
		FakeHttp::json( array( 'data' => array( 'abuseConfidenceScore' => 10 ) ) );
		FakeHttp::json( array( 'data' => array( 'abuseConfidenceScore' => 60 ) ) );

		$this->assertSame( 10, ( new AbuseIPDB( 'key' ) )->check_ip( '8.8.8.8' )->get_confidence_score() );
		$this->assertSame( 60, ( new AbuseIPDB( 'key', array( 'max_age_days' => 365 ) ) )->check_ip( '8.8.8.8' )->get_confidence_score() );
	}

	/**
	 * The common answer: score, abusive at 75, Tor, hosting from the usage
	 * type, and nothing about VPNs.
	 *
	 * @return void
	 */
	public function test_lookup(): void {
		FakeHttp::json(
			array(
				'data' => array(
					'abuseConfidenceScore' => 75,
					'countryCode'          => 'DE',
					'usageType'            => 'Data Center/Web Hosting/Transit',
					'isTor'                => false,
					'isp'                  => 'Hetzner',
				),
			)
		);

		$result = ( new AbuseIPDB( 'key' ) )->lookup( '8.8.8.8' );

		$this->assertInstanceOf( Result::class, $result );
		$this->assertSame( 'abuseipdb', $result->get_provider() );
		$this->assertSame( 75, $result->get_risk_score() );
		$this->assertTrue( $result->is_abusive() );
		$this->assertTrue( $result->is_hosting() );
		$this->assertFalse( $result->is_tor() );
		$this->assertNull( $result->is_vpn() );
		$this->assertSame( 'DE', $result->get_country_code() );
		$this->assertSame( 'Hetzner', $result->get_isp() );
		$this->assertSame( 'datacenter/webhosting/transit', $result->get_connection_type() );
	}

	/**
	 * A residential line is not hosting; no usage type is no answer.
	 *
	 * @return void
	 */
	public function test_lookup_hosting_from_usage_type(): void {
		FakeHttp::json( array( 'data' => array( 'abuseConfidenceScore' => 0, 'usageType' => 'Fixed Line ISP' ) ) );
		FakeHttp::json( array( 'data' => array( 'abuseConfidenceScore' => 74 ) ) );

		$this->assertFalse( ( new AbuseIPDB( 'key' ) )->lookup( '8.8.8.8' )->is_hosting() );

		$other = ( new AbuseIPDB( 'key' ) )->lookup( '1.1.1.1' );
		$this->assertNull( $other->is_hosting() );
		$this->assertFalse( $other->is_abusive() );
	}
}
