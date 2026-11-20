<?php
/**
 * IPinfo tests.
 *
 * @package SugarCommerce\IpLookup
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Tests\Providers;

use PHPUnit\Framework\TestCase;
use SugarCommerce\IpLookup\Models\IPInfo\Response;
use SugarCommerce\IpLookup\Providers\IPInfo;
use SugarCommerce\IpLookup\Tests\Support\FakeHttp;

/**
 * One address, many, single fields, plans, and the common answer.
 */
final class IPInfoTest extends TestCase {

	/**
	 * @return void
	 */
	protected function setUp(): void {
		ipl_reset();
	}

	/**
	 * What the free plan answers.
	 *
	 * @return array
	 */
	private static function free(): array {
		return array(
			'ip'       => '8.8.8.8',
			'hostname' => 'dns.google',
			'anycast'  => true,
			'city'     => 'Mountain View',
			'region'   => 'California',
			'country'  => 'us',
			'loc'      => '37.4056,-122.0775',
			'org'      => 'AS15169 Google LLC',
			'postal'   => '94043',
			'timezone' => 'America/Los_Angeles',
		);
	}

	/**
	 * What the Business plan adds.
	 *
	 * @return array
	 */
	private static function business(): array {
		return self::free() + array(
			'asn'     => array(
				'asn'    => 'AS15169',
				'name'   => 'Google LLC',
				'domain' => 'google.com',
				'route'  => '8.8.8.0/24',
				'type'   => 'hosting',
			),
			'company' => array(
				'name'   => 'Google LLC',
				'domain' => 'google.com',
				'type'   => 'hosting',
			),
			'privacy' => array(
				'vpn'     => false,
				'proxy'   => false,
				'tor'     => false,
				'relay'   => true,
				'hosting' => true,
				'service' => 'iCloud Private Relay',
			),
			'abuse'   => array(
				'email'   => 'network-abuse@google.com',
				'country' => 'US',
			),
		);
	}

	/**
	 * The free plan: location, country helpers from sugarcommerce/geo, and
	 * the coordinates read from `loc`.
	 *
	 * @return void
	 */
	public function test_free_plan(): void {
		FakeHttp::json( self::free() );

		$info = ( new IPInfo( 'token' ) )->get_ip_info( '8.8.8.8' );

		$this->assertInstanceOf( Response::class, $info );
		$this->assertSame( 'Free', $info->get_plan() );
		$this->assertFalse( $info->has_feature( 'asn' ) );
		$this->assertSame( 'dns.google', $info->get_hostname() );
		$this->assertTrue( $info->is_anycast() );
		$this->assertSame( 'US', $info->get_country() );
		$this->assertSame( 'United States', $info->get_country_name() );
		$this->assertSame( "\u{1F1FA}\u{1F1F8}", $info->get_country_flag() );
		$this->assertSame( array( 'code' => 'NA', 'name' => 'North America' ), $info->get_continent() );
		$this->assertFalse( $info->is_eu() );
		$this->assertSame( array( 'latitude' => 37.4056, 'longitude' => -122.0775 ), $info->get_coordinates() );
		$this->assertSame( -122.0775, $info->get_longitude() );
		$this->assertSame( '94043', $info->get_postal() );
		$this->assertNull( $info->get_asn() );
		$this->assertNull( $info->get_privacy() );

		$request = FakeHttp::last();
		$this->assertSame( 'https://ipinfo.io/8.8.8.8', $request['url'] );
		$this->assertSame( 'Bearer token', $request['args']['headers']['Authorization'] );
	}

	/**
	 * Without a token, no Authorization header at all.
	 *
	 * @return void
	 */
	public function test_no_token_sends_no_header(): void {
		FakeHttp::json( self::free() );

		( new IPInfo() )->get_ip_info( '8.8.8.8' );

		$this->assertArrayNotHasKey( 'Authorization', FakeHttp::last()['args']['headers'] );
	}

	/**
	 * The Business plan's blocks.
	 *
	 * @return void
	 */
	public function test_business_plan(): void {
		FakeHttp::json( self::business() + array( 'domains' => array( 'total' => 2, 'domains' => array( 'a.com', 'b.com' ), 'page' => 0 ) ) );

		$info = ( new IPInfo( 'token' ) )->get_ip_info( '8.8.8.8' );

		$this->assertSame( 'Premium', $info->get_plan() );
		$this->assertTrue( $info->has_feature( 'domains' ) );
		$this->assertSame( 'AS15169', $info->get_asn()->get_asn() );
		$this->assertSame( '8.8.8.0/24', $info->get_asn()->get_route() );
		$this->assertSame( 'hosting', $info->get_company()->get_type() );
		$this->assertTrue( $info->get_privacy()->is_relay() );
		$this->assertSame( 'iCloud Private Relay', $info->get_privacy()->get_service() );
		$this->assertSame( 'network-abuse@google.com', $info->get_abuse()->get_email() );
		$this->assertNull( $info->get_abuse()->get_phone() );
		$this->assertSame( 2, $info->get_domains()->get_total() );
	}

	/**
	 * An error in the body is an error.
	 *
	 * @return void
	 */
	public function test_error_in_body(): void {
		FakeHttp::json( array( 'error' => array( 'title' => 'Wrong token', 'message' => 'Please ensure your token is valid.' ) ) );

		$error = ( new IPInfo( 'bad' ) )->get_ip_info( '8.8.8.8' );

		$this->assertSame( 'ipinfo_api_error', $error->get_error_code() );
		$this->assertSame( 'Please ensure your token is valid.', $error->get_error_message() );
	}

	/**
	 * A status that is not 2xx is an error.
	 *
	 * @return void
	 */
	public function test_http_status(): void {
		FakeHttp::json( array(), 429 );

		$this->assertSame( 'ipinfo_api_error', ( new IPInfo( 'token' ) )->get_ip_info( '8.8.8.8' )->get_error_code() );
	}

	/**
	 * A batch asks only for what is not cached, and caches what it gets.
	 *
	 * @return void
	 */
	public function test_batch_uses_the_cache(): void {
		FakeHttp::json( self::free() );
		FakeHttp::json( array( '1.1.1.1' => array( 'ip' => '1.1.1.1', 'country' => 'AU' ) ) );
		$client = new IPInfo( 'token' );
		$client->get_ip_info( '8.8.8.8' );

		$results = $client->get_batch_info( array( '8.8.8.8', '1.1.1.1', '10.0.0.1', '1.1.1.1' ) );

		$this->assertSame( array( '8.8.8.8', '1.1.1.1' ), array_keys( $results ) );
		$this->assertSame( 'AU', $results['1.1.1.1']->get_country() );
		$this->assertSame( '["1.1.1.1"]', FakeHttp::last()['args']['body'] );
		$this->assertSame( 'https://ipinfo.io/batch', FakeHttp::last()['url'] );

		$this->assertSame( 'AU', $client->get_ip_info( '1.1.1.1' )->get_country() );
		$this->assertSame( 2, FakeHttp::count() );
	}

	/**
	 * Nothing public to ask about is an error, with no request.
	 *
	 * @return void
	 */
	public function test_batch_of_nothing(): void {
		$this->assertSame( 'ipinfo_invalid_ips', ( new IPInfo( 'token' ) )->get_batch_info( array( '127.0.0.1', 'x' ) )->get_error_code() );
		$this->assertSame( 0, FakeHttp::count() );
	}

	/**
	 * One field comes back as plain text.
	 *
	 * @return void
	 */
	public function test_field_is_plain_text(): void {
		FakeHttp::raw( "US\n" );
		FakeHttp::raw( 'Mountain View' );
		$client = new IPInfo( 'token' );

		$this->assertSame( 'US', $client->get_field( '8.8.8.8', 'country' ) );
		$this->assertSame( 'https://ipinfo.io/8.8.8.8/country', FakeHttp::last()['url'] );
		$this->assertSame( array( 'country' => 'US', 'city' => 'Mountain View' ), $client->get_fields( '8.8.8.8', array( 'country', 'city' ) ) );
		$this->assertSame( 'ipinfo_invalid_field', $client->get_field( '8.8.8.8', '../batch' )->get_error_code() );
	}

	/**
	 * The free plan's common answer reads the ASN out of `org`, and says
	 * nothing about privacy.
	 *
	 * @return void
	 */
	public function test_lookup_free(): void {
		FakeHttp::json( self::free() );

		$result = ( new IPInfo( 'token' ) )->lookup( '8.8.8.8' );

		$this->assertSame( 'AS15169', $result->get_asn() );
		$this->assertSame( 'Google LLC', $result->get_isp() );
		$this->assertSame( 'NA', $result->get_continent_code() );
		$this->assertFalse( $result->is_eu() );
		$this->assertSame( 37.4056, $result->get_latitude() );
		$this->assertNull( $result->is_vpn() );
		$this->assertNull( $result->is_hosting() );
		$this->assertNull( $result->get_risk_score() );
	}

	/**
	 * The Business plan's common answer has the privacy flags.
	 *
	 * @return void
	 */
	public function test_lookup_business(): void {
		FakeHttp::json( self::business() );

		$result = ( new IPInfo( 'token' ) )->lookup( '8.8.8.8' );

		$this->assertFalse( $result->is_vpn() );
		$this->assertTrue( $result->is_relay() );
		$this->assertTrue( $result->is_hosting() );
		$this->assertFalse( $result->is_anonymous() );
		$this->assertSame( 'hosting', $result->get_connection_type() );
		$this->assertSame( 'Google LLC', $result->get_organisation() );
	}
}
