<?php
/**
 * Lookup tests.
 *
 * @package SugarCommerce\IpLookup
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\IpLookup\Lookup;
use SugarCommerce\IpLookup\Models\Result;
use SugarCommerce\IpLookup\Providers\AbuseIPDB;
use SugarCommerce\IpLookup\Providers\IPQualityScore;
use SugarCommerce\IpLookup\Tests\Support\FakeHttp;

/**
 * Several providers as one.
 */
final class LookupTest extends TestCase {

	/**
	 * @return void
	 */
	protected function setUp(): void {
		ipl_reset();
	}

	/**
	 * The second provider is asked only when the first fails.
	 *
	 * @return void
	 */
	public function test_first_falls_back(): void {
		FakeHttp::fail();
		FakeHttp::json( array( 'success' => true, 'fraud_score' => 12 ) );
		$lookup = new Lookup( new AbuseIPDB( 'k' ), new IPQualityScore( 'k' ) );

		$result = $lookup->first( '8.8.8.8' );

		$this->assertSame( 'ipqualityscore', $result->get_provider() );
		$this->assertSame( 2, FakeHttp::count() );
	}

	/**
	 * When the first answers, the second costs nothing.
	 *
	 * @return void
	 */
	public function test_first_stops_at_an_answer(): void {
		FakeHttp::json( array( 'data' => array( 'abuseConfidenceScore' => 3 ) ) );

		$this->assertSame( 'abuseipdb', ( new Lookup( new AbuseIPDB( 'k' ), new IPQualityScore( 'k' ) ) )->first( '8.8.8.8' )->get_provider() );
		$this->assertSame( 1, FakeHttp::count() );
	}

	/**
	 * All failing is the last failure; no providers is its own error.
	 *
	 * @return void
	 */
	public function test_first_failures(): void {
		FakeHttp::fail();
		FakeHttp::fail();

		$this->assertSame( 'ipqualityscore_http_error', ( new Lookup( new AbuseIPDB( 'k' ), new IPQualityScore( 'k' ) ) )->first( '8.8.8.8' )->get_error_code() );
		$this->assertSame( 'iplookup_no_provider', ( new Lookup() )->first( '8.8.8.8' )->get_error_code() );
	}

	/**
	 * All answers, keyed by provider, each asked once per request.
	 *
	 * @return void
	 */
	public function test_all_is_asked_once(): void {
		FakeHttp::json( array( 'data' => array( 'abuseConfidenceScore' => 3 ) ) );
		FakeHttp::fail();
		$lookup = new Lookup( new AbuseIPDB( 'k', array( 'cache' => false ) ), new IPQualityScore( 'k', array( 'cache' => false ) ) );

		$answers = $lookup->all( '8.8.8.8' );
		$lookup->all( '8.8.8.8' );

		$this->assertInstanceOf( Result::class, $answers['abuseipdb'] );
		$this->assertTrue( is_wp_error( $answers['ipqualityscore'] ) );
		$this->assertSame( 2, FakeHttp::count() );
		$this->assertCount( 2, $lookup->get_providers() );

		$lookup->reset();
		FakeHttp::json( array( 'data' => array() ) );
		$lookup->ask( $lookup->get_providers()[0], '8.8.8.8' );
		$this->assertSame( 3, FakeHttp::count() );
	}
}
