<?php
/**
 * ProxyCheck tests.
 *
 * @package SugarCommerce\IpLookup
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Tests\Providers;

use PHPUnit\Framework\TestCase;
use SugarCommerce\IpLookup\Providers\ProxyCheck;
use SugarCommerce\IpLookup\Tests\Support\FakeHttp;

/**
 * Checks, the block verdict, email, batches, the dashboard and the common
 * answer.
 */
final class ProxyCheckTest extends TestCase {

	/**
	 * @return void
	 */
	protected function setUp(): void {
		ipl_reset();
	}

	/**
	 * ProxyCheck's answer for one address.
	 *
	 * @param string $ip    The address.
	 * @param array  $entry What it says about it.
	 *
	 * @return void
	 */
	private function queue( string $ip, array $entry ): void {
		FakeHttp::json(
			array(
				'status' => 'ok',
				'node'   => 'EOS',
				$ip      => $entry,
			)
		);
	}

	/**
	 * A VPN with its operator: blocked as a VPN, with the operator's details.
	 *
	 * @return void
	 */
	public function test_vpn_is_blocked_with_details(): void {
		$this->queue(
			'8.8.8.8',
			array(
				'proxy'        => 'yes',
				'type'         => 'VPN',
				'risk'         => 66,
				'asn'          => 'AS9009',
				'provider'     => 'M247',
				'organisation' => 'Mullvad',
				'country'      => 'Sweden',
				'isocode'      => 'SE',
				'europe'       => 1,
				'continent'    => 'Europe',
				'continentcode' => 'EU',
				'operator'     => array(
					'name'       => 'Mullvad',
					'anonymity'  => 'high',
					'popularity' => 'high',
					'policies'   => array( 'no_logs' => true ),
				),
			)
		);

		$check = ( new ProxyCheck( 'key' ) )->check_ip( '8.8.8.8' );

		$this->assertTrue( $check->should_block() );
		$this->assertSame( 'vpn', $check->get_block_reason() );
		$this->assertSame( 'Mullvad', $check->get_block_details()['name'] );
		$this->assertTrue( $check->is_vpn() );
		$this->assertSame( array( 'name' => 'Sweden', 'code' => 'SE', 'is_eu' => true ), $check->get_country() );
		$this->assertSame( '8.8.8.8', $check->get_ip() );
		$this->assertTrue( $check->get_operator_policies()['no_logs'] );
		$this->assertStringContainsString( 'key=key', FakeHttp::last()['url'] );
		$this->assertStringStartsWith( 'https://proxycheck.io/v2/8.8.8.8?', FakeHttp::last()['url'] );
	}

	/**
	 * A risk over 70 blocks on its own; 70 does not.
	 *
	 * @return void
	 */
	public function test_risk_over_seventy_blocks(): void {
		$this->queue( '8.8.8.8', array( 'proxy' => 'no', 'risk' => 71, 'country' => 'France', 'isocode' => 'FR' ) );
		$this->queue( '1.1.1.1', array( 'proxy' => 'no', 'risk' => 70, 'country' => 'France', 'isocode' => 'FR' ) );
		$client = new ProxyCheck( 'key' );

		$this->assertSame( 'high_risk', $client->check_ip( '8.8.8.8' )->get_block_reason() );
		$this->assertFalse( $client->check_ip( '1.1.1.1' )->should_block() );
	}

	/**
	 * A blocked country blocks a clean address; an allowed one lets a proxy
	 * through; and the countries take effect without a new request.
	 *
	 * @return void
	 */
	public function test_country_rules(): void {
		$this->queue( '8.8.8.8', array( 'proxy' => 'no', 'country' => 'Russia', 'isocode' => 'RU' ) );
		$this->queue( '1.1.1.1', array( 'proxy' => 'yes', 'type' => 'SOCKS', 'country' => 'United Kingdom', 'isocode' => 'GB' ) );
		$client = new ProxyCheck( 'key' );
		$client->set_blocked_countries( array( 'ru' ) );

		$this->assertTrue( $client->get_asn() );
		$this->assertSame( 'country', $client->check_ip( '8.8.8.8' )->get_block_reason() );

		$client->set_allowed_countries( array( 'United Kingdom' ) );
		$this->assertFalse( $client->check_ip( '1.1.1.1' )->should_block() );

		$client->set_blocked_countries( array() );
		$this->assertFalse( $client->check_ip( '8.8.8.8' )->should_block() );
		$this->assertSame( 2, FakeHttp::count() );
	}

	/**
	 * Without a country a proxy is still blocked; a clean address has no
	 * verdict only when the client blocks by country.
	 *
	 * @return void
	 */
	public function test_no_country(): void {
		$this->queue( '8.8.8.8', array( 'proxy' => 'yes', 'type' => 'HTTP' ) );
		$this->queue( '1.1.1.1', array( 'proxy' => 'no' ) );
		$client = new ProxyCheck( 'key' );

		$this->assertTrue( $client->check_ip( '8.8.8.8' )->should_block() );
		$this->assertSame( 'na', $client->check_ip( '1.1.1.1' )->get_block_reason() );
		$this->assertSame( 'no', $client->check_ip( '1.1.1.1' )->get( 'block' ) );

		$client->set_blocked_countries( array( 'RU' ) );
		$this->assertSame( 'na', $client->check_ip( '1.1.1.1' )->get( 'block' ) );
	}

	/**
	 * Refusals come in `status`.
	 *
	 * @return void
	 */
	public function test_status_refusals(): void {
		FakeHttp::json( array( 'status' => 'denied', 'message' => '1,000 free queries exhausted.' ) );
		FakeHttp::json( array( 'status' => 'error', 'message' => 'Bad key' ) );

		$this->assertSame( '1,000 free queries exhausted.', ( new ProxyCheck( 'k' ) )->check_ip( '8.8.8.8' )->get_error_message() );
		$this->assertSame( 'proxycheck_api_error', ( new ProxyCheck( 'k' ) )->check_ip( '1.1.1.1' )->get_error_code() );
	}

	/**
	 * The flags are bounded, and what they send.
	 *
	 * @return void
	 */
	public function test_parameters(): void {
		$client = new ProxyCheck();

		$this->assertSame( 'proxycheck_invalid_vpn_mode', $client->set_vpn( 4 )->get_error_code() );
		$this->assertSame( 'proxycheck_invalid_risk_level', $client->set_risk( 3 )->get_error_code() );
		$this->assertSame( 'proxycheck_invalid_days', $client->set_days( 0 )->get_error_code() );
		$client->set_vpn( 3 )->set_inf( true )->set_port( true )->set_seen( true )->set_node( true )->set_time( true );
		$client->set_query_tagging( true );

		$this->assertSame( 'Test Shop', $client->get_tag() );
		$this->assertSame( 3, $client->get_vpn() );
		$this->assertTrue( $client->get_inf() && $client->get_port() && $client->get_seen() && $client->get_node() && $client->get_time() );
		$this->assertSame( 600, $client->get_cache_ttl() );

		$this->queue( '8.8.8.8', array( 'proxy' => 'no' ) );
		$client->check_ip( '8.8.8.8' );
		$this->assertStringContainsString( 'vpn=3', FakeHttp::last()['url'] );
		$this->assertStringNotContainsString( 'key=', FakeHttp::last()['url'] );
	}

	/**
	 * A disposable email is blocked; masking sends only the domain.
	 *
	 * @return void
	 */
	public function test_email(): void {
		$this->queue( 'anonymous@mailinator.com', array( 'disposable' => 'yes' ) );

		$check = ( new ProxyCheck( 'k' ) )->check_email( 'someone@mailinator.com', true );

		$this->assertTrue( $check->is_disposable() );
		$this->assertTrue( $check->should_block() );
		$this->assertSame( 'disposable', $check->get_block_reason() );
		$this->assertStringStartsWith( 'https://proxycheck.io/v2/anonymous%40mailinator.com', FakeHttp::last()['url'] );
		$this->assertSame( 'proxycheck_invalid_email', ( new ProxyCheck( 'k' ) )->check_email( 'nope' )->get_error_code() );
	}

	/**
	 * A batch is one POST, each address with its own verdict.
	 *
	 * @return void
	 */
	public function test_batch(): void {
		FakeHttp::json(
			array(
				'status'  => 'ok',
				'8.8.8.8' => array( 'proxy' => 'yes', 'type' => 'VPN' ),
				'1.1.1.1' => array( 'proxy' => 'no' ),
			)
		);

		$results = ( new ProxyCheck( 'k' ) )->check_ips( array( '8.8.8.8', '1.1.1.1', '192.168.0.1' ) );

		$this->assertSame( array( '8.8.8.8', '1.1.1.1' ), array_keys( $results ) );
		$this->assertTrue( $results['8.8.8.8']->should_block() );
		$this->assertFalse( $results['1.1.1.1']->is_proxy() );
		$this->assertSame( '8.8.8.8,1.1.1.1', FakeHttp::last()['args']['body']['ips'] );
		$this->assertSame( 'proxycheck_invalid_ips', ( new ProxyCheck( 'k' ) )->check_ips( array( '10.0.0.1' ) )->get_error_code() );
	}

	/**
	 * The dashboard needs a key, caches its exports unless forced, and
	 * reads and changes the lists.
	 *
	 * @return void
	 */
	public function test_dashboard(): void {
		$this->assertSame( 'proxycheck_missing_key', ( new ProxyCheck() )->get_usage()->get_error_code() );
		$this->assertSame( 0, ( new ProxyCheck() )->get_used_tokens() );

		$usage = array(
			'Queries Today'    => '250',
			'Daily Limit'      => '1000',
			'Queries Total'    => '9000',
			'Plan Tier'        => 'Free',
			'Burst Tokens Available' => 2,
			'Burst Token Allowance'  => 5,
		);
		FakeHttp::json( $usage );
		FakeHttp::json( $usage );
		$client = new ProxyCheck( 'k' );

		$this->assertSame( 250, $client->get_used_tokens() );
		$this->assertSame( 1000, $client->get_token_limit() );
		$this->assertSame( 25.0, $client->get_usage_percentage() );
		$this->assertFalse( $client->is_token_limit_exceeded() );
		$this->assertSame( 1, FakeHttp::count() );
		$client->get_usage( true );
		$this->assertSame( 2, FakeHttp::count() );

		FakeHttp::json( array( 'status' => 'denied', 'message' => 'Dashboard API access is off.' ) );
		$this->assertSame( 'proxycheck_api_access_denied', $client->get_blacklist()->get_error_code() );
		$this->assertStringStartsWith( 'https://proxycheck.io/dashboard/blacklist/list/?json=1&key=k', FakeHttp::last()['url'] );

		FakeHttp::json( array( 'status' => 'ok' ) );
		$client->add_to_blacklist( array( ' 8.8.8.8 ', '', '1.1.1.1' ) );
		$this->assertSame( 'POST', FakeHttp::last()['method'] );
		$this->assertSame( "8.8.8.8\n1.1.1.1", FakeHttp::last()['args']['body']['data'] );

		FakeHttp::json( array( 'status' => 'ok' ) );
		$client->get_cors_origins();
		$this->assertStringStartsWith( 'https://proxycheck.io/dashboard/cors/list/', FakeHttp::last()['url'] );
		$this->assertSame( 'proxycheck_invalid_action', $client->manage_list( 'drop', 'whitelist' )->get_error_code() );
		$this->assertSame( 'proxycheck_invalid_list', $client->manage_list( 'print', '../x' )->get_error_code() );
	}

	/**
	 * The common answer asks with the VPN operator, the network and the
	 * risk on.
	 *
	 * @return void
	 */
	public function test_lookup(): void {
		$this->queue(
			'8.8.8.8',
			array(
				'proxy'         => 'yes',
				'type'          => 'TOR',
				'risk'          => 100,
				'asn'           => 'AS16276',
				'provider'      => 'OVH SAS',
				'country'       => 'France',
				'isocode'       => 'FR',
				'europe'        => 1,
				'continentcode' => 'EU',
				'continent'     => 'Europe',
				'city'          => 'Roubaix',
				'region'        => 'Hauts-de-France',
				'latitude'      => 50.69,
				'longitude'     => 3.17,
				'network'       => array( 'type' => 'Hosting' ),
			)
		);

		$result = ( new ProxyCheck( 'k' ) )->lookup( '8.8.8.8' );

		$this->assertSame( 100, $result->get_risk_score() );
		$this->assertTrue( $result->is_tor() );
		$this->assertFalse( $result->is_vpn() );
		$this->assertTrue( $result->is_hosting() );
		$this->assertTrue( $result->is_eu() );
		$this->assertSame( 'EU', $result->get_continent_code() );
		$this->assertSame( 'Hauts-de-France', $result->get_region() );
		$this->assertSame( 50.69, $result->get_latitude() );
		$this->assertSame( 'OVH SAS', $result->get_isp() );

		$url = FakeHttp::last()['url'];
		$this->assertStringContainsString( 'vpn=1', $url );
		$this->assertStringContainsString( 'asn=1', $url );
		$this->assertStringContainsString( 'risk=1', $url );
	}
}
