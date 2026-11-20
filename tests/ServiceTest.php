<?php
/**
 * Service tests: the cache, the failure memory and refused addresses,
 * through AbuseIPDB as the simplest provider.
 *
 * @package SugarCommerce\IpLookup
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\IpLookup\Models\AbuseIPDB\Check;
use SugarCommerce\IpLookup\Providers\AbuseIPDB;
use SugarCommerce\IpLookup\Tests\Support\FakeHttp;
use WP_Error;

/**
 * What every provider shares.
 */
final class ServiceTest extends TestCase {

	/**
	 * @return void
	 */
	protected function setUp(): void {
		ipl_reset();
	}

	/**
	 * An answer AbuseIPDB might give.
	 *
	 * @param int $score The score.
	 *
	 * @return void
	 */
	private function queue( int $score = 10 ): void {
		FakeHttp::json( array( 'data' => array( 'abuseConfidenceScore' => $score ) ) );
	}

	/**
	 * A second ask is answered from the cache.
	 *
	 * @return void
	 */
	public function test_answer_is_cached(): void {
		$this->queue( 42 );
		$client = new AbuseIPDB( 'key' );

		$this->assertSame( 42, $client->check_ip( '8.8.8.8' )->get_confidence_score() );
		$this->assertSame( 42, $client->check_ip( '8.8.8.8' )->get_confidence_score() );
		$this->assertSame( 1, FakeHttp::count() );
	}

	/**
	 * An answer is kept for the cache lifetime and no longer.
	 *
	 * @return void
	 */
	public function test_answer_expires(): void {
		$this->queue( 1 );
		$this->queue( 2 );
		$client = new AbuseIPDB( 'key', array( 'cache_ttl' => 100 ) );

		$client->check_ip( '8.8.8.8' );
		ipl_advance( 99 );
		$this->assertSame( 1, $client->check_ip( '8.8.8.8' )->get_confidence_score() );
		ipl_advance( 1 );
		$this->assertSame( 2, $client->check_ip( '8.8.8.8' )->get_confidence_score() );
	}

	/**
	 * A failure is remembered, so the next visitor does not wait out the
	 * timeout -- and forgotten after the failure lifetime.
	 *
	 * @return void
	 */
	public function test_failure_is_remembered_briefly(): void {
		FakeHttp::fail();
		$this->queue( 7 );
		$client = new AbuseIPDB( 'key' );

		$this->assertSame( 'abuseipdb_http_error', $client->check_ip( '8.8.8.8' )->get_error_code() );
		$this->assertSame( 'abuseipdb_recent_failure', $client->check_ip( '8.8.8.8' )->get_error_code() );
		$this->assertSame( 1, FakeHttp::count() );

		ipl_advance( 60 );
		$this->assertSame( 7, $client->check_ip( '8.8.8.8' )->get_confidence_score() );
		$this->assertSame( 2, FakeHttp::count() );
	}

	/**
	 * A failure lifetime of 0 retries every time.
	 *
	 * @return void
	 */
	public function test_failure_ttl_zero_retries(): void {
		FakeHttp::fail();
		FakeHttp::fail();
		$client = new AbuseIPDB( 'key', array( 'failure_ttl' => 0 ) );

		$client->check_ip( '8.8.8.8' );
		$client->check_ip( '8.8.8.8' );
		$this->assertSame( 2, FakeHttp::count() );
	}

	/**
	 * A failure for one address does not blind the client to another.
	 *
	 * @return void
	 */
	public function test_failure_is_per_question(): void {
		FakeHttp::fail();
		$this->queue( 3 );
		$client = new AbuseIPDB( 'key' );

		$client->check_ip( '8.8.8.8' );
		$this->assertInstanceOf( Check::class, $client->check_ip( '1.1.1.1' ) );
	}

	/**
	 * With the cache off, nothing is read, kept, or remembered.
	 *
	 * @return void
	 */
	public function test_cache_off_asks_every_time(): void {
		FakeHttp::fail();
		$this->queue();
		$this->queue();
		$client = new AbuseIPDB( 'key', array( 'cache' => false ) );

		$this->assertInstanceOf( WP_Error::class, $client->check_ip( '8.8.8.8' ) );
		$client->check_ip( '8.8.8.8' );
		$client->check_ip( '8.8.8.8' );
		$this->assertSame( 3, FakeHttp::count() );
		$this->assertSame( array(), $GLOBALS['ipl_transients'] );
	}

	/**
	 * Two keys never share an answer.
	 *
	 * @return void
	 */
	public function test_cache_is_per_key(): void {
		$this->queue( 1 );
		$this->queue( 2 );

		$this->assertSame( 1, ( new AbuseIPDB( 'one' ) )->check_ip( '8.8.8.8' )->get_confidence_score() );
		$this->assertSame( 2, ( new AbuseIPDB( 'two' ) )->check_ip( '8.8.8.8' )->get_confidence_score() );
	}

	/**
	 * Clearing one answer, then every answer with the prefix.
	 *
	 * @return void
	 */
	public function test_clear_cache(): void {
		$this->queue();
		$this->queue();
		$client = new AbuseIPDB( 'key' );
		$client->check_ip( '8.8.8.8' );
		$client->check_ip( '1.1.1.1' );
		set_transient( 'unrelated', 1 );

		$this->assertTrue( $client->clear_cache( '8.8.8.8|90' ) );
		$this->assertCount( 2, $GLOBALS['ipl_transients'] );

		$this->assertTrue( $client->clear_cache() );
		$this->assertSame( array( 'unrelated' ), array_keys( $GLOBALS['ipl_transients'] ) );
	}

	/**
	 * With a persistent object cache the transients are not in the options
	 * table, so finding them by name finds nothing -- clearing everything
	 * must still mean the next ask goes to the provider.
	 *
	 * @return void
	 */
	public function test_clear_cache_with_a_persistent_object_cache(): void {
		$GLOBALS['ipl_object_cache'] = true;
		$this->queue( 10 );
		$this->queue( 20 );
		$this->queue( 30 );
		$client = new AbuseIPDB( 'key' );

		$this->assertSame( 10, $client->check_ip( '8.8.8.8' )->get_confidence_score() );
		$this->assertTrue( $client->clear_cache() );
		$this->assertSame( 20, $client->check_ip( '8.8.8.8' )->get_confidence_score() );
		$this->assertSame( 20, $client->check_ip( '8.8.8.8' )->get_confidence_score() );

		// Another client of the same provider shares the clearing.
		$this->assertTrue( ( new AbuseIPDB( 'key' ) )->clear_cache() );
		$this->assertSame( 30, $client->check_ip( '8.8.8.8' )->get_confidence_score() );
		$this->assertSame( 3, FakeHttp::count() );

		// One answer is still cleared by its own key.
		$this->assertTrue( $client->clear_cache( '8.8.8.8|90' ) );
	}

	/**
	 * Answers kept before anything was ever cleared are still found.
	 *
	 * @return void
	 */
	public function test_keys_are_unchanged_until_the_first_clear(): void {
		$this->queue( 10 );
		( new AbuseIPDB( 'key' ) )->check_ip( '8.8.8.8' );

		$this->assertSame( array( 'iplookup_abuseipdb_' . md5( '8.8.8.8|90|key' ) ), array_keys( $GLOBALS['ipl_transients'] ) );
	}

	/**
	 * Addresses not on the public internet are refused before any request.
	 *
	 * @param string $ip The address.
	 *
	 * @return void
	 */
	#[DataProvider( 'not_public' )]
	public function test_non_public_address_costs_nothing( string $ip ): void {
		$result = ( new AbuseIPDB( 'key' ) )->check_ip( $ip );

		$this->assertSame( 'abuseipdb_invalid_ip', $result->get_error_code() );
		$this->assertSame( 0, FakeHttp::count() );
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function not_public(): array {
		return array(
			'empty'         => array( '' ),
			'garbage'       => array( 'not-an-ip' ),
			'private'       => array( '192.168.1.10' ),
			'loopback'      => array( '127.0.0.1' ),
			'documentation' => array( '203.0.113.9' ),
			'cgnat'         => array( '100.64.0.1' ),
			'v6 loopback'   => array( '::1' ),
			'nat64 private' => array( '64:ff9b::7f00:1' ),
		);
	}

	/**
	 * The settings are held to what makes sense.
	 *
	 * @return void
	 */
	public function test_settings_are_bounded(): void {
		$client = new AbuseIPDB( 'key', array( 'cache_ttl' => -5, 'failure_ttl' => -1, 'max_age_days' => 900 ) );

		$this->assertSame( 0, $client->get_cache_ttl() );
		$this->assertSame( 0, $client->get_failure_ttl() );
		$this->assertSame( 365, $client->get_max_age_days() );
		$this->assertSame( 1, $client->set_max_age_days( 0 )->get_max_age_days() );
		$this->assertSame( 3600, ( new AbuseIPDB() )->get_cache_ttl() );
		$this->assertSame( 'abuseipdb', $client->get_id() );
		$this->assertSame( 'AbuseIPDB', $client->get_name() );
	}
}
