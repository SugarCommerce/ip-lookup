<?php
/**
 * Conditions tests.
 *
 * @package SugarCommerce\IpLookup
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\Conditions\Conditions as Rules;
use SugarCommerce\Conditions\Registry;
use SugarCommerce\IpLookup\Conditions;
use SugarCommerce\IpLookup\Provider;
use SugarCommerce\IpLookup\Providers\AbuseIPDB;
use SugarCommerce\IpLookup\Providers\IPInfo;
use SugarCommerce\IpLookup\Providers\IPQualityScore;
use SugarCommerce\IpLookup\Providers\ProxyCheck;
use SugarCommerce\IpLookup\Result;
use SugarCommerce\IpLookup\Tests\Support\FakeHttp;
use WP_Error;

/**
 * The services' conditions, under wp-conditions' ids.
 */
final class ConditionsTest extends TestCase {

	/**
	 * @return void
	 */
	protected function setUp(): void {
		ipl_reset();
		Conditions::reset();
		Rules::reset();
		Registry::reset();
	}

	/**
	 * Every id wp-conditions had for these services is here, so saved rules
	 * keep working.
	 *
	 * @return void
	 */
	public function test_old_ids_survive(): void {
		$ids = array_merge(
			array_keys( Conditions::definitions( new ProxyCheck() ) ),
			array_keys( Conditions::definitions( new IPQualityScore() ) ),
			array_keys( Conditions::definitions( new IPInfo() ) ),
			array_keys( Conditions::definitions( new AbuseIPDB() ) )
		);

		$old = array(
			'abuseipdb_confidence_score', 'abuseipdb_is_abusive', 'abuseipdb_total_reports', 'abuseipdb_country', 'abuseipdb_is_tor', 'abuseipdb_is_whitelisted',
			'ipinfo_country', 'ipinfo_region', 'ipinfo_is_eu', 'ipinfo_asn', 'ipinfo_asn_type', 'ipinfo_is_vpn', 'ipinfo_is_proxy', 'ipinfo_is_tor', 'ipinfo_is_relay', 'ipinfo_is_hosting', 'ipinfo_is_suspicious',
			'ipqs_fraud_score', 'ipqs_is_high_risk', 'ipqs_is_proxy', 'ipqs_is_vpn', 'ipqs_is_tor', 'ipqs_is_bot', 'ipqs_recent_abuse', 'ipqs_is_suspicious', 'ipqs_country', 'ipqs_asn', 'ipqs_connection_type', 'ipqs_isp', 'ipqs_is_disposable_email', 'ipqs_is_valid_email', 'ipqs_is_leaked_email', 'ipqs_is_risky_email',
			'proxycheck_risk_score', 'proxycheck_is_high_risk', 'proxycheck_is_proxy', 'proxycheck_is_vpn', 'proxycheck_is_suspicious', 'proxycheck_should_block', 'proxycheck_type', 'proxycheck_country', 'proxycheck_continent', 'proxycheck_is_eu', 'proxycheck_city', 'proxycheck_asn', 'proxycheck_provider', 'proxycheck_organisation', 'proxycheck_network_type', 'proxycheck_operator', 'proxycheck_no_logs_policy', 'proxycheck_accepts_crypto', 'proxycheck_accepts_anonymous', 'proxycheck_is_free_vpn', 'proxycheck_is_disposable_email',
		);

		sort( $old );
		sort( $ids );
		$this->assertSame( $old, $ids );
	}

	/**
	 * A lookup that failed is no answer -- null, never false or 0 -- and is
	 * asked for once however many conditions read it.
	 *
	 * @return void
	 */
	public function test_failure_is_no_answer(): void {
		FakeHttp::fail();
		$conditions = Conditions::definitions( new IPQualityScore( 'k' ) );
		$args       = array( 'ip' => '8.8.8.8' );

		$this->assertNull( $conditions['ipqs_is_vpn']['compare_value']( $args ) );
		$this->assertNull( $conditions['ipqs_fraud_score']['compare_value']( $args ) );
		$this->assertNull( $conditions['ipqs_is_suspicious']['compare_value']( $args ) );
		$this->assertNull( $conditions['ipqs_country']['compare_value']( $args ) );
		$this->assertSame( 1, FakeHttp::count() );
	}

	/**
	 * Answers, read through the conditions, once per address.
	 *
	 * @return void
	 */
	public function test_answers(): void {
		FakeHttp::json(
			array(
				'success'         => true,
				'fraud_score'     => 80,
				'proxy'           => false,
				'vpn'             => true,
				'tor'             => false,
				'recent_abuse'    => false,
				'country_code'    => 'gb',
				'connection_type' => 'Data Center',
			)
		);
		$conditions = Conditions::definitions( new IPQualityScore( 'k' ) );
		$args       = array( 'ip_address' => '8.8.8.8' );

		$this->assertTrue( $conditions['ipqs_is_vpn']['compare_value']( $args ) );
		$this->assertTrue( $conditions['ipqs_is_suspicious']['compare_value']( $args ) );
		$this->assertTrue( $conditions['ipqs_is_high_risk']['compare_value']( $args ) );
		$this->assertSame( 80, $conditions['ipqs_fraud_score']['compare_value']( $args ) );
		$this->assertSame( 'GB', $conditions['ipqs_country']['compare_value']( $args ) );
		$this->assertSame( 'datacenter', $conditions['ipqs_connection_type']['compare_value']( $args ) );
		$this->assertSame( 1, FakeHttp::count() );
	}

	/**
	 * Email conditions need the email, and read it once.
	 *
	 * @return void
	 */
	public function test_email_conditions(): void {
		FakeHttp::json( array( 'success' => true, 'valid' => true, 'disposable' => false, 'leaked' => true ) );
		$conditions = Conditions::definitions( new IPQualityScore( 'k' ) );
		$args       = array( 'email' => 'a@example.com' );

		$this->assertSame( array( 'email' ), $conditions['ipqs_is_risky_email']['required_args'] );
		$this->assertTrue( $conditions['ipqs_is_risky_email']['compare_value']( $args ) );
		$this->assertTrue( $conditions['ipqs_is_leaked_email']['compare_value']( $args ) );
		$this->assertTrue( $conditions['ipqs_is_valid_email']['compare_value']( $args ) );
		$this->assertSame( 1, FakeHttp::count() );
	}

	/**
	 * A VPN's operator and the brands sharing its exit, lower case; its
	 * policies; and a clean address answering no.
	 *
	 * @return void
	 */
	public function test_proxycheck_operator(): void {
		FakeHttp::json(
			array(
				'status'  => 'ok',
				'8.8.8.8' => array(
					'proxy'    => 'yes',
					'type'     => 'VPN',
					'network'  => array( 'type' => 'Residential' ),
					'operator' => array(
						'name'                 => 'Hide.me',
						'additional_operators' => array( 'Mullvad', '', 'hide.me' ),
						'policies'             => array( 'no_logs' => true, 'free_vpn' => false ),
					),
				),
			)
		);
		FakeHttp::json( array( 'status' => 'ok', '1.1.1.1' => array( 'proxy' => 'no' ) ) );
		$conditions = Conditions::definitions( new ProxyCheck( 'k' ) );
		$vpn        = array( 'ip' => '8.8.8.8' );
		$clean      = array( 'ip' => '1.1.1.1' );

		$this->assertSame( array( 'hide.me', 'mullvad' ), $conditions['proxycheck_operator']['compare_value']( $vpn ) );
		$this->assertTrue( $conditions['proxycheck_no_logs_policy']['compare_value']( $vpn ) );
		$this->assertFalse( $conditions['proxycheck_is_free_vpn']['compare_value']( $vpn ) );
		$this->assertTrue( $conditions['proxycheck_is_vpn']['compare_value']( $vpn ) );
		$this->assertSame( 'VPN', $conditions['proxycheck_type']['compare_value']( $vpn ) );
		$this->assertSame( 'Residential', $conditions['proxycheck_network_type']['compare_value']( $vpn ) );

		$this->assertSame( array(), $conditions['proxycheck_operator']['compare_value']( $clean ) );
		$this->assertFalse( $conditions['proxycheck_no_logs_policy']['compare_value']( $clean ) );
		$this->assertFalse( $conditions['proxycheck_is_suspicious']['compare_value']( $clean ) );
		$this->assertSame( 2, FakeHttp::count() );
	}

	/**
	 * IPinfo without a privacy block (a plan below Business) gives no
	 * answer about VPNs, not "no".
	 *
	 * @return void
	 */
	public function test_ipinfo_without_privacy_is_no_answer(): void {
		FakeHttp::json( array( 'ip' => '8.8.8.8', 'country' => 'DE' ) );
		$conditions = Conditions::definitions( new IPInfo( 'k' ) );
		$args       = array( 'ip' => '8.8.8.8' );

		$this->assertNull( $conditions['ipinfo_is_vpn']['compare_value']( $args ) );
		$this->assertNull( $conditions['ipinfo_is_suspicious']['compare_value']( $args ) );
		$this->assertTrue( $conditions['ipinfo_is_eu']['compare_value']( $args ) );
		$this->assertSame( 'DE', $conditions['ipinfo_country']['compare_value']( $args ) );
	}

	/**
	 * Without an `ip` argument the address is the request's.
	 *
	 * @return void
	 */
	public function test_address_from_the_request(): void {
		$_SERVER['REMOTE_ADDR'] = '8.8.4.4';

		$this->assertSame( '8.8.4.4', Conditions::ip( array() ) );
		$this->assertSame( '1.1.1.1', Conditions::ip( array( 'ip' => ' 1.1.1.1 ', 'ip_address' => '9.9.9.9' ) ) );

		Rules::provide( 'ip', fn () => '9.9.9.9' );
		$this->assertSame( '9.9.9.9', Conditions::ip( array() ) );
	}

	/**
	 * A provider of your own gets the common conditions.
	 *
	 * @return void
	 */
	public function test_own_provider(): void {
		$provider = new class() implements Provider {

			/**
			 * @return string
			 */
			public function get_id(): string {
				return 'mine';
			}

			/**
			 * @return string
			 */
			public function get_name(): string {
				return 'Mine';
			}

			/**
			 * @param string $ip The address.
			 *
			 * @return Result|WP_Error
			 */
			public function lookup( string $ip ): Result|WP_Error {
				return new Result( 'mine', $ip, array( 'risk_score' => 33, 'is_tor' => true, 'country_code' => 'fr' ) );
			}
		};

		$conditions = Conditions::definitions( $provider );

		$this->assertSame( array( 'mine_risk_score', 'mine_is_proxy', 'mine_is_vpn', 'mine_is_tor', 'mine_is_hosting', 'mine_country' ), array_keys( $conditions ) );
		$this->assertSame( 33, $conditions['mine_risk_score']['compare_value']( array( 'ip' => '8.8.8.8' ) ) );
		$this->assertTrue( $conditions['mine_is_tor']['compare_value']( array( 'ip' => '8.8.8.8' ) ) );
		$this->assertNull( $conditions['mine_is_vpn']['compare_value']( array( 'ip' => '8.8.8.8' ) ) );
		$this->assertSame( 'FR', $conditions['mine_country']['compare_value']( array( 'ip' => '8.8.8.8' ) ) );
	}

	/**
	 * Registered into a set, a rule built on them matches -- and a failed
	 * lookup matches neither "yes" nor "no".
	 *
	 * @return void
	 */
	public function test_rules_match(): void {
		FakeHttp::json( array( 'data' => array( 'abuseConfidenceScore' => 90, 'isTor' => false ) ) );
		FakeHttp::fail();
		Conditions::register( 'fraud_rule', new AbuseIPDB( 'k' ) );

		$this->assertNotNull( Registry::get_condition( 'fraud_rule', 'abuseipdb_is_abusive' ) );

		$abusive = array( array( 'rules' => array( array( 'condition' => 'abuseipdb_is_abusive', 'operator' => 'yes', 'value' => '' ) ) ) );
		$not_tor = array( array( 'rules' => array( array( 'condition' => 'abuseipdb_is_tor', 'operator' => 'no', 'value' => '' ) ) ) );

		$this->assertTrue( Rules::matches( 'fraud_rule', $abusive, array( 'ip' => '8.8.8.8' ) ) );
		$this->assertTrue( Rules::matches( 'fraud_rule', $not_tor, array( 'ip' => '8.8.8.8' ) ) );
		$this->assertFalse( Rules::matches( 'fraud_rule', $not_tor, array( 'ip' => '1.1.1.1' ) ) );
		$this->assertFalse( Rules::matches( 'fraud_rule', $abusive, array( 'ip' => '1.1.1.1' ) ) );
	}
}
