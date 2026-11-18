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
use SugarCommerce\IpLookup\Providers\IPQualityScore\Response\CountryList;
use SugarCommerce\IpLookup\Providers\IPQualityScore\Response\EntryList;
use SugarCommerce\IpLookup\Providers\IPQualityScore\Response\MalwareCheck;
use SugarCommerce\IpLookup\Providers\IPQualityScore\Transaction;
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
	 * Email, phone and URL checks validate first and go to their endpoints.
	 *
	 * @return void
	 */
	public function test_email_phone_url(): void {
		FakeHttp::json( array( 'success' => true, 'valid' => true, 'disposable' => true, 'leaked' => false ) );
		FakeHttp::json( array( 'success' => true, 'valid' => true, 'VOIP' => true ) );
		FakeHttp::json( array( 'success' => true, 'unsafe' => true, 'risk_score' => 100 ) );
		$client = new IPQualityScore( 'k' );

		$email = $client->validate_email( 'a@example.com' );
		$this->assertTrue( $email->is_disposable() );
		$this->assertSame( 'https://ipqualityscore.com/api/json/email/k', FakeHttp::last()['url'] );
		$this->assertSame( 'a@example.com', FakeHttp::last()['args']['body']['email'] );

		$this->assertTrue( $client->validate_phone( '+1 (555) 010-9999' )->is_voip() );
		$this->assertStringStartsWith( 'https://ipqualityscore.com/api/json/phone/k/15550109999', FakeHttp::last()['url'] );

		$this->assertTrue( $client->scan_url( 'https://example.com/a?b=c' )->is_unsafe() );
		$this->assertStringStartsWith( 'https://ipqualityscore.com/api/json/url/k/https%3A%2F%2Fexample.com%2Fa%3Fb%3Dc?', FakeHttp::last()['url'] );

		$this->assertSame( 'ipqualityscore_invalid_email', $client->validate_email( 'nope' )->get_error_code() );
		$this->assertSame( 'ipqualityscore_invalid_phone', $client->validate_phone( '12345' )->get_error_code() );
		$this->assertSame( 'ipqualityscore_invalid_url', $client->scan_url( 'nope' )->get_error_code() );
		$this->assertSame( 3, FakeHttp::count() );
	}

	/**
	 * A leak check puts the type before the key, and never keeps the value
	 * in a transient's name.
	 *
	 * @return void
	 */
	public function test_leak_check(): void {
		FakeHttp::json( array( 'success' => true, 'exposed' => true ) );
		$client = new IPQualityScore( 'k' );

		$this->assertTrue( $client->check_leaked_data( 'hunter2', 'password' )->is_exposed() );
		$this->assertStringStartsWith( 'https://ipqualityscore.com/api/json/leaked/password/k/hunter2', FakeHttp::last()['url'] );

		foreach ( array_keys( $GLOBALS['ipl_transients'] ) as $key ) {
			$this->assertStringNotContainsString( 'hunter2', $key );
		}

		$this->assertSame( 'ipqualityscore_invalid_type', $client->check_leaked_data( 'x', 'phone' )->get_error_code() );
		$this->assertSame( 'ipqualityscore_invalid_username', $client->check_leaked_data( '', 'username' )->get_error_code() );
	}

	/**
	 * A file is sent as multipart, with its bytes.
	 *
	 * @return void
	 */
	public function test_scan_file(): void {
		$file = tempnam( sys_get_temp_dir(), 'ipl' );
		file_put_contents( $file, 'EICAR-ish' );
		FakeHttp::json( array( 'success' => true, 'status' => 'cached', 'result' => array() ) );

		$check = ( new IPQualityScore( 'k' ) )->scan_file_for_malware( $file );
		unlink( $file );

		$this->assertInstanceOf( MalwareCheck::class, $check );
		$request = FakeHttp::last();
		$this->assertSame( 'https://ipqualityscore.com/api/json/malware/scan/k', $request['url'] );
		$this->assertStringStartsWith( 'multipart/form-data; boundary=', $request['args']['headers']['Content-Type'] );
		$this->assertStringContainsString( "\r\n\r\nEICAR-ish\r\n", $request['args']['body'] );
		$this->assertSame( 'ipqualityscore_invalid_file', ( new IPQualityScore( 'k' ) )->scan_file_for_malware( '/no/such/file' )->get_error_code() );
		$this->assertSame( 'ipqualityscore_invalid_hash', ( new IPQualityScore( 'k' ) )->lookup_malware_hash( 'abc' )->get_error_code() );
	}

	/**
	 * A transaction can be an array or the builder, needs an address, and is
	 * never cached.
	 *
	 * @return void
	 */
	public function test_transaction(): void {
		FakeHttp::json( array( 'success' => true, 'fraud_score' => 5 ) );
		FakeHttp::json( array( 'success' => true, 'fraud_score' => 6 ) );
		$client      = new IPQualityScore( 'k' );
		$transaction = ( new Transaction() )->set_ip_address( '8.8.8.8' )->set_billing( array( 'country' => 'GB' ) );

		$this->assertSame( 5, $client->validate_transaction( $transaction )->get_fraud_score() );
		$this->assertSame( '8.8.8.8', FakeHttp::last()['args']['body']['ip_address'] );
		$this->assertSame( 6, $client->validate_transaction( $transaction )->get_fraud_score() );
		$this->assertSame( 'ipqualityscore_missing_field', $client->validate_transaction( array() )->get_error_code() );
	}

	/**
	 * A report needs something to report, and a phone needs its country.
	 *
	 * @return void
	 */
	public function test_report_validation(): void {
		$client = new IPQualityScore( 'k' );

		$this->assertSame( 'ipqualityscore_missing_parameter', $client->report_fraud( array() )->get_error_code() );
		$this->assertSame( 'ipqualityscore_invalid_ip', $client->report_ip( 'x' )->get_error_code() );
		$this->assertSame( 'ipqualityscore_missing_country', $client->report_fraud( array( 'phone' => '5550109999' ) )->get_error_code() );
		$this->assertSame( 'ipqualityscore_invalid_phone', $client->report_phone( 'abc', 'US' )->get_error_code() );
		$this->assertSame( 0, FakeHttp::count() );

		FakeHttp::json( array( 'success' => true ) );
		$this->assertTrue( $client->report_request( 'req-1' )->is_success() );
		$this->assertSame( 'https://ipqualityscore.com/api/json/report/k', FakeHttp::last()['url'] );
	}

	/**
	 * Request lists default to the last 30 days, check their dates, and skip
	 * the common parameters.
	 *
	 * @return void
	 */
	public function test_request_list(): void {
		FakeHttp::json( array( 'success' => true, 'requests' => array(), 'total_pages' => '3' ) );
		$client = new IPQualityScore( 'k' );

		$this->assertSame( 3, $client->get_request_list( 'proxy' )->get_total_pages() );
		$url = FakeHttp::last()['url'];
		$this->assertStringStartsWith( 'https://ipqualityscore.com/api/json/requests/k/list?type=proxy&start_date=', $url );
		$this->assertStringNotContainsString( 'strictness', $url );

		$this->assertSame( 'ipqualityscore_invalid_date', $client->get_request_list( 'proxy', array( 'start_date' => '2026-02-30' ) )->get_error_code() );
		$this->assertSame( 'ipqualityscore_invalid_type', $client->get_request_list( 'url' )->get_error_code() );
	}

	/**
	 * Allow and block list entries are checked against their type.
	 *
	 * @return void
	 */
	public function test_list_entries(): void {
		$client = new IPQualityScore( 'k' );

		$this->assertSame( 'ipqualityscore_invalid_type', $client->create_allowlist_entry( '8.8.8.8', 'nope', 'ip' )->get_error_code() );
		$this->assertSame( 'ipqualityscore_invalid_value_type', $client->create_blocklist_entry( 'a@example.com', 'proxy', 'email' )->get_error_code() );
		$this->assertSame( 'ipqualityscore_invalid_value', $client->create_blocklist_entry( '8.8.8.8/99', 'proxy', 'cidr' )->get_error_code() );
		$this->assertSame( 0, FakeHttp::count() );

		FakeHttp::json( array( 'success' => true, 'data' => array() ) );
		$this->assertInstanceOf( EntryList::class, $client->create_allowlist_entry( '8.8.8.0/24', 'proxy', 'cidr', 'office' ) );
		$this->assertSame( 'https://ipqualityscore.com/api/json/allowlist/create/k', FakeHttp::last()['url'] );
		$this->assertSame( 'office', FakeHttp::last()['args']['body']['reason'] );

		FakeHttp::json( array( 'success' => true, 'data' => array() ) );
		$client->get_blocklist_entries();
		$this->assertStringStartsWith( 'https://ipqualityscore.com/api/json/blocklist/list/k?', FakeHttp::last()['url'] );
	}

	/**
	 * Credit usage is kept for five minutes at most; the country list a day.
	 *
	 * @return void
	 */
	public function test_cache_lifetimes(): void {
		FakeHttp::json( array( 'success' => true, 'credits' => 5000, 'usage' => 1000 ) );
		FakeHttp::json( array( 'countries' => array( 'GB' => 'United Kingdom' ) ) );
		$client = new IPQualityScore( 'k' );

		$client->get_credit_usage();
		$list = $client->get_country_list();

		$this->assertInstanceOf( CountryList::class, $list );
		$this->assertSame( 'United Kingdom', $list->get_country_name( 'GB' ) );

		$expiries = array_column( $GLOBALS['ipl_transients'], 'expires' );
		sort( $expiries );
		$this->assertSame( array( $GLOBALS['ipl_now'] + 300, $GLOBALS['ipl_now'] + DAY_IN_SECONDS ), $expiries );
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
