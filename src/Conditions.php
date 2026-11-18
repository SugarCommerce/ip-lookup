<?php
/**
 * Conditions
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup;

use SugarCommerce\Conditions\Conditions as Rules;
use SugarCommerce\Conditions\Helpers\Geo as GeoOptions;
use SugarCommerce\Conditions\Helpers\Request as RuleRequest;
use SugarCommerce\Conditions\Operators;
use SugarCommerce\Geo\Countries;
use SugarCommerce\IpLookup\Providers\AbuseIPDB;
use SugarCommerce\IpLookup\Providers\IPInfo;
use SugarCommerce\IpLookup\Providers\IPQualityScore;
use SugarCommerce\IpLookup\Providers\ProxyCheck;
use SugarCommerce\IpLookup\Providers\ProxyCheck\Response\IP as ProxyCheckIP;
use WP_Error;

/**
 * Class Conditions
 *
 * Each service's answers as conditions in a sugarcommerce/conditions rule
 * builder -- "Proxy is yes", "Fraud Score is at least 75", "VPN Operator is
 * any of Mullvad" -- under the ids wp-conditions gave them, so rules saved
 * against those ids keep working.
 *
 * Hand register() the clients, already holding their keys:
 *
 *     Conditions::register( 'fraud_rule', new ProxyCheck( $key ), new IPQualityScore( $other_key ) );
 *
 * The address is the `ip` argument, or `ip_address`, or whatever the
 * conditions library resolves (its `ip` provider, else REMOTE_ADDR). Email
 * conditions need an `email` argument.
 *
 * A lookup that fails is no answer, never "no": the condition gives null
 * and the rule does not match, so "VPN is no" cannot pass because the
 * service was down. Each answer is asked for once per request, whichever
 * and however many conditions read it.
 *
 * @since 1.0.0
 */
final class Conditions {

	/**
	 * Answers already given in this request.
	 *
	 * @var array<string, mixed>
	 */
	private static array $answers = array();

	/**
	 * Add a set's conditions for each provider.
	 *
	 * @since 1.0.0
	 *
	 * @param string   $set_id       The rule set, as registered with sugarcommerce/conditions.
	 * @param Provider ...$providers The clients.
	 *
	 * @return void
	 */
	public static function register( string $set_id, Provider ...$providers ): void {
		foreach ( $providers as $provider ) {
			foreach ( self::definitions( $provider ) as $id => $config ) {
				Rules::add( $set_id, $id, $config );
			}
		}
	}

	/**
	 * The conditions for one provider, by id.
	 *
	 * A provider of your own gets the common ones, named after its id:
	 * `{id}_risk_score`, `{id}_is_proxy`, `{id}_is_vpn`, `{id}_is_tor`,
	 * `{id}_is_hosting`, `{id}_country`.
	 *
	 * @since 1.0.0
	 *
	 * @param Provider $provider The client.
	 *
	 * @return array<string, array> Condition configurations.
	 */
	public static function definitions( Provider $provider ): array {
		return match ( true ) {
			$provider instanceof ProxyCheck     => self::proxycheck( $provider ),
			$provider instanceof IPQualityScore => self::ipqualityscore( $provider ),
			$provider instanceof IPInfo         => self::ipinfo( $provider ),
			$provider instanceof AbuseIPDB      => self::abuseipdb( $provider ),
			default                             => self::common( $provider ),
		};
	}

	/**
	 * Forget the answers kept for this request.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public static function reset(): void {
		self::$answers = array();
	}

	/**
	 * The address a rule is about.
	 *
	 * @since 1.0.0
	 *
	 * @param array $args The rule's arguments.
	 *
	 * @return string Empty when there is none.
	 */
	public static function ip( array $args ): string {
		foreach ( array( 'ip', 'ip_address' ) as $key ) {
			if ( isset( $args[ $key ] ) && is_scalar( $args[ $key ] ) && '' !== trim( (string) $args[ $key ] ) ) {
				return trim( (string) $args[ $key ] );
			}
		}

		return (string) RuleRequest::get_ip( $args );
	}

	/**
	 * ProxyCheck's conditions.
	 *
	 * @param ProxyCheck $client The client.
	 *
	 * @return array<string, array>
	 */
	private static function proxycheck( ProxyCheck $client ): array {
		$group = __( 'ProxyCheck', 'sugarcommerce' );
		$check = fn ( array $args ): ?ProxyCheckIP => self::proxycheck_check( $client, $args );
		$entry = function ( array $args ) use ( $check ): ?array {
			$response = $check( $args );

			return null === $response ? null : (array) ( $response->to_array()[ self::ip( $args ) ] ?? array() );
		};
		$type  = fn ( array $args ): ?string => null === $check( $args ) ? null : strtoupper( (string) $check( $args )->get_type() );

		$policy = function ( string $name ) use ( $entry ): \Closure {
			return function ( array $args ) use ( $entry, $name ): ?bool {
				$data = $entry( $args );

				return null === $data ? null : ! empty( $data['operator']['policies'][ $name ] );
			};
		};

		return array(
			'proxycheck_risk_score'          => self::number( $group, __( 'Risk Score', 'sugarcommerce' ), __( 'ProxyCheck risk score (0-100). Common thresholds: 50 and over suspicious, 80 and over likely fraud, 90 and over almost certainly fraud.', 'sugarcommerce' ), fn ( $args ) => $check( $args )?->get_risk_score(), 50 ),
			'proxycheck_is_high_risk'        => self::boolean( $group, __( 'High Risk', 'sugarcommerce' ), __( 'Yes when the risk score is 50 or above.', 'sugarcommerce' ), fn ( $args ) => null === $check( $args )?->get_risk_score() ? null : $check( $args )->get_risk_score() >= 50 ),
			'proxycheck_is_proxy'            => self::boolean( $group, __( 'Proxy', 'sugarcommerce' ), __( 'Yes when the address is on ProxyCheck\'s proxy list -- data centre, hosting or public proxy addresses. Use Suspicious to catch proxies and VPNs in one check.', 'sugarcommerce' ), fn ( $args ) => $check( $args )?->is_proxy() ),
			'proxycheck_is_vpn'              => self::boolean( $group, __( 'VPN', 'sugarcommerce' ), __( 'Yes when the address is a commercial VPN exit. Many careful customers use one, so pair it with another signal before blocking.', 'sugarcommerce' ), fn ( $args ) => null === $check( $args ) ? null : 'VPN' === $type( $args ) ),
			'proxycheck_is_suspicious'       => self::boolean( $group, __( 'Suspicious', 'sugarcommerce' ), __( 'Yes when the address is a proxy or a VPN.', 'sugarcommerce' ), fn ( $args ) => null === $check( $args ) ? null : ( $check( $args )->is_proxy() || 'VPN' === $type( $args ) ) ),
			'proxycheck_should_block'        => self::boolean( $group, __( 'Should Block', 'sugarcommerce' ), __( 'Yes when the address is a proxy or a VPN, its risk is over 70, or its country is blocked in the client\'s settings.', 'sugarcommerce' ), fn ( $args ) => $check( $args )?->should_block() ),
			'proxycheck_type'                => self::choice( $group, __( 'Proxy Type', 'sugarcommerce' ), __( 'Which kind of proxy or VPN it is -- VPN, Tor, SOCKS, a public proxy. Lets a rule allow some kinds and block others.', 'sugarcommerce' ), self::options( array( 'VPN', 'TOR', 'SOCKS', 'SOCKS4', 'SOCKS4A', 'SOCKS5', 'SOCKS5H', 'Shadowsocks', 'HTTP', 'HTTPS', 'Compromised Server', 'Inference Engine', 'OpenVPN', 'WireGuard' ) ), fn ( $args ) => null === $check( $args ) ? null : (string) $check( $args )->get_type() ),
			'proxycheck_country'             => self::country( $group, fn ( $args ) => null === $check( $args ) ? null : ( $check( $args )->get_country()['code'] ?? '' ) ),
			'proxycheck_continent'           => self::choice( $group, __( 'Continent', 'sugarcommerce' ), __( 'The continent the address is in.', 'sugarcommerce' ), self::continents(), fn ( $args ) => null === $check( $args ) ? null : ( $check( $args )->get_continent()['code'] ?? '' ) ),
			'proxycheck_is_eu'               => self::boolean( $group, __( 'EU Country', 'sugarcommerce' ), __( 'Yes when the address is in a member state of the European Union.', 'sugarcommerce' ), fn ( $args ) => null === $check( $args ) ? null : (bool) ( $check( $args )->get_country()['is_eu'] ?? false ) ),
			'proxycheck_city'                => self::text( $group, __( 'City', 'sugarcommerce' ), __( 'The city the address is in. Approximate: usually right to the metro area, no closer.', 'sugarcommerce' ), fn ( $args ) => null === $check( $args ) ? null : (string) $check( $args )->get_city() ),
			'proxycheck_asn'                 => self::tags( $group, __( 'ASN', 'sugarcommerce' ), __( 'The network the address is on, as AS15169. Blocks a whole hosting network at once.', 'sugarcommerce' ), fn ( $args ) => null === $check( $args ) ? null : (string) $check( $args )->get_asn() ),
			'proxycheck_provider'            => self::tags( $group, __( 'Provider', 'sugarcommerce' ), __( 'The internet provider\'s name, to match against a watch list.', 'sugarcommerce' ), fn ( $args ) => null === $check( $args ) ? null : (string) $check( $args )->get_provider() ),
			'proxycheck_organisation'        => self::tags( $group, __( 'Organisation', 'sugarcommerce' ), __( 'The organisation the address block is registered to -- often the provider, not always.', 'sugarcommerce' ), fn ( $args ) => null === $check( $args ) ? null : (string) $check( $args )->get_organisation() ),
			'proxycheck_network_type'        => self::choice( $group, __( 'Network Type', 'sugarcommerce' ), __( 'The connection underneath: hosting, residential, mobile or business. A residential line on a VPN is network Residential and type VPN.', 'sugarcommerce' ), self::options( array( 'Hosting', 'Residential', 'Mobile', 'Business' ) ), fn ( $args ) => null === $entry( $args ) ? null : (string) ( $entry( $args )['network']['type'] ?? '' ) ),
			'proxycheck_operator'            => self::tags( $group, __( 'VPN Operator', 'sugarcommerce' ), __( 'The VPN service -- Mullvad, NordVPN. Matches services sharing the exit too: a rule for Mullvad matches an address listed under Hide.me with Mullvad beside it.', 'sugarcommerce' ), fn ( $args ) => null === $entry( $args ) ? null : self::operator_names( $entry( $args ) ) ),
			'proxycheck_no_logs_policy'      => self::boolean( $group, __( 'No-Logs Policy', 'sugarcommerce' ), __( 'Yes when the VPN says it keeps no logs.', 'sugarcommerce' ), $policy( 'no_logs' ) ),
			'proxycheck_accepts_crypto'      => self::boolean( $group, __( 'Accepts Crypto Payments', 'sugarcommerce' ), __( 'Yes when the VPN takes cryptocurrency.', 'sugarcommerce' ), $policy( 'accepts_crypto_payments' ) ),
			'proxycheck_accepts_anonymous'   => self::boolean( $group, __( 'Accepts Anonymous Payments', 'sugarcommerce' ), __( 'Yes when the VPN takes cash, gift cards or other payments that name nobody.', 'sugarcommerce' ), $policy( 'accepts_anonymous_payments' ) ),
			'proxycheck_is_free_vpn'         => self::boolean( $group, __( 'Free VPN', 'sugarcommerce' ), __( 'Yes when the VPN costs nothing, so no card on file ties it to anyone.', 'sugarcommerce' ), $policy( 'free_vpn' ) ),
			'proxycheck_is_disposable_email' => self::boolean(
				$group,
				__( 'Disposable Email', 'sugarcommerce' ),
				__( 'Yes when the email address is from a throwaway service.', 'sugarcommerce' ),
				function ( array $args ) use ( $client ): ?bool {
					$email = self::answer( $client, 'email', (string) $args['email'], fn () => $client->check_email( (string) $args['email'] ) );

					return is_wp_error( $email ) ? null : $email->is_disposable();
				},
				array( 'email' )
			),
		);
	}

	/**
	 * IPQualityScore's conditions.
	 *
	 * @param IPQualityScore $client The client.
	 *
	 * @return array<string, array>
	 */
	private static function ipqualityscore( IPQualityScore $client ): array {
		$group = __( 'IPQualityScore', 'sugarcommerce' );
		$check = function ( array $args ) use ( $client ): ?Providers\IPQualityScore\Response\IP {
			$ip     = self::ip( $args );
			$answer = '' === $ip ? null : self::answer( $client, 'ip', $ip, fn () => $client->check_ip( $ip ) );

			return null === $answer || is_wp_error( $answer ) ? null : $answer;
		};
		$email = function ( array $args ) use ( $client ): ?Providers\IPQualityScore\Response\Email {
			$answer = self::answer( $client, 'email', (string) $args['email'], fn () => $client->validate_email( (string) $args['email'] ) );

			return is_wp_error( $answer ) ? null : $answer;
		};

		return array(
			'ipqs_fraud_score'         => self::number( $group, __( 'Fraud Score', 'sugarcommerce' ), __( 'IPQualityScore fraud score (0-100): 75 and over suspicious, 85 and over high risk, 90 and over likely fraud.', 'sugarcommerce' ), fn ( $args ) => null === $check( $args ) ? null : (int) $check( $args )->get_fraud_score(), 75 ),
			'ipqs_is_high_risk'        => self::boolean( $group, __( 'High Risk', 'sugarcommerce' ), __( 'Yes when the fraud score is 75 or above.', 'sugarcommerce' ), fn ( $args ) => null === $check( $args ) ? null : (int) $check( $args )->get_fraud_score() >= 75 ),
			'ipqs_is_proxy'            => self::boolean( $group, __( 'Proxy', 'sugarcommerce' ), __( 'Yes when the address is a proxy -- data centre, hosting or public. Use Suspicious for proxies, VPNs, Tor and recent abuse in one check.', 'sugarcommerce' ), fn ( $args ) => $check( $args )?->is_proxy() ),
			'ipqs_is_vpn'              => self::boolean( $group, __( 'VPN', 'sugarcommerce' ), __( 'Yes when the address is a commercial VPN exit.', 'sugarcommerce' ), fn ( $args ) => $check( $args )?->is_vpn() ),
			'ipqs_is_tor'              => self::boolean( $group, __( 'Tor', 'sugarcommerce' ), __( 'Yes when the address is a Tor exit node -- rare among real buyers.', 'sugarcommerce' ), fn ( $args ) => $check( $args )?->is_tor() ),
			'ipqs_is_bot'              => self::boolean( $group, __( 'Bot/Automation', 'sugarcommerce' ), __( 'Yes when the address behaves like a bot: scraping, credential stuffing, scripted checkouts.', 'sugarcommerce' ), fn ( $args ) => $check( $args )?->is_bot() ),
			'ipqs_recent_abuse'        => self::boolean( $group, __( 'Recent Abuse', 'sugarcommerce' ), __( 'Yes when other sites have reported abuse from the address lately -- chargebacks, spam, account takeovers.', 'sugarcommerce' ), fn ( $args ) => $check( $args )?->has_recent_abuse() ),
			'ipqs_is_suspicious'       => self::boolean( $group, __( 'Suspicious', 'sugarcommerce' ), __( 'Yes when the address is a proxy, a VPN, Tor, or has recent abuse.', 'sugarcommerce' ), fn ( $args ) => null === $check( $args ) ? null : ( $check( $args )->is_proxy() || $check( $args )->is_vpn() || $check( $args )->is_tor() || $check( $args )->has_recent_abuse() ) ),
			'ipqs_country'             => self::country( $group, fn ( $args ) => null === $check( $args ) ? null : (string) $check( $args )->get_country_code() ),
			'ipqs_asn'                 => self::tags( $group, __( 'ASN', 'sugarcommerce' ), __( 'The network the address is on, as the bare number: 15169.', 'sugarcommerce' ), fn ( $args ) => null === $check( $args ) ? null : (string) $check( $args )->get_asn() ),
			'ipqs_connection_type'     => self::choice(
				$group,
				__( 'Connection Type', 'sugarcommerce' ),
				__( 'How the address connects: residential, mobile, corporate, education or data centre.', 'sugarcommerce' ),
				array(
					array(
						'value' => 'residential',
						'label' => __( 'Residential', 'sugarcommerce' ),
					),
					array(
						'value' => 'corporate',
						'label' => __( 'Corporate', 'sugarcommerce' ),
					),
					array(
						'value' => 'education',
						'label' => __( 'Education', 'sugarcommerce' ),
					),
					array(
						'value' => 'mobile',
						'label' => __( 'Mobile', 'sugarcommerce' ),
					),
					array(
						'value' => 'datacenter',
						'label' => __( 'Data Center', 'sugarcommerce' ),
					),
				),
				// The API says "Data Center"; the options say "datacenter".
				fn ( $args ) => null === $check( $args ) ? null : strtolower( str_replace( ' ', '', (string) $check( $args )->get_connection_type() ) )
			),
			'ipqs_isp'                 => self::tags( $group, __( 'ISP', 'sugarcommerce' ), __( 'The internet provider\'s name. For a whole hosting network, ASN is more precise.', 'sugarcommerce' ), fn ( $args ) => null === $check( $args ) ? null : (string) $check( $args )->get_isp() ),
			'ipqs_is_disposable_email' => self::boolean( $group, __( 'Disposable Email', 'sugarcommerce' ), __( 'Yes when the email address is from a throwaway service.', 'sugarcommerce' ), fn ( $args ) => $email( $args )?->is_disposable(), array( 'email' ) ),
			'ipqs_is_valid_email'      => self::boolean( $group, __( 'Valid Email', 'sugarcommerce' ), __( 'Yes when the address can receive mail: good MX records, a mailbox that exists.', 'sugarcommerce' ), fn ( $args ) => $email( $args )?->is_valid(), array( 'email' ) ),
			'ipqs_is_leaked_email'     => self::boolean( $group, __( 'Leaked Email', 'sugarcommerce' ), __( 'Yes when the address has turned up in a data breach -- worth a closer look on a new, large order.', 'sugarcommerce' ), fn ( $args ) => $email( $args )?->is_leaked(), array( 'email' ) ),
			'ipqs_is_risky_email'      => self::boolean( $group, __( 'Risky Email', 'sugarcommerce' ), __( 'Yes when the address is disposable, undeliverable or leaked.', 'sugarcommerce' ), fn ( $args ) => null === $email( $args ) ? null : ( $email( $args )->is_disposable() || ! $email( $args )->is_valid() || $email( $args )->is_leaked() ), array( 'email' ) ),
		);
	}

	/**
	 * IPinfo's conditions.
	 *
	 * @param IPInfo $client The client.
	 *
	 * @return array<string, array>
	 */
	private static function ipinfo( IPInfo $client ): array {
		$group   = __( 'IPinfo', 'sugarcommerce' );
		$info    = function ( array $args ) use ( $client ): ?Providers\IPInfo\Response {
			$ip     = self::ip( $args );
			$answer = '' === $ip ? null : self::answer( $client, 'ip', $ip, fn () => $client->get_ip_info( $ip ) );

			return null === $answer || is_wp_error( $answer ) ? null : $answer;
		};
		$privacy = function ( string $flag ) use ( $info ): \Closure {
			return function ( array $args ) use ( $info, $flag ): ?bool {
				$response = $info( $args );

				// No privacy block is a plan without one: no answer.
				return null === $response?->get_privacy() ? null : $response->get_privacy()->{'is_' . $flag}();
			};
		};

		return array(
			'ipinfo_country'       => self::country( $group, fn ( $args ) => null === $info( $args ) ? null : (string) $info( $args )->get_country() ),
			'ipinfo_region'        => self::text( $group, __( 'Region/State', 'sugarcommerce' ), __( 'The region or state, by name -- California, England. Approximate.', 'sugarcommerce' ), fn ( $args ) => null === $info( $args ) ? null : (string) $info( $args )->get_region() ),
			'ipinfo_is_eu'         => self::boolean( $group, __( 'EU Country', 'sugarcommerce' ), __( 'Yes when the address is in a member state of the European Union.', 'sugarcommerce' ), fn ( $args ) => $info( $args )?->is_eu() ),
			'ipinfo_asn'           => self::tags( $group, __( 'ASN', 'sugarcommerce' ), __( 'The network the address is on, as AS15169. Basic plan and above.', 'sugarcommerce' ), fn ( $args ) => null === $info( $args ) ? null : (string) $info( $args )->get_asn()?->get_asn() ),
			'ipinfo_asn_type'      => self::choice( $group, __( 'Network Type', 'sugarcommerce' ), __( 'What kind of network it is. Hosting at a checkout is a strong fraud signal.', 'sugarcommerce' ), self::options( array( 'isp', 'hosting', 'business', 'education' ), array( __( 'ISP', 'sugarcommerce' ), __( 'Hosting', 'sugarcommerce' ), __( 'Business', 'sugarcommerce' ), __( 'Education', 'sugarcommerce' ) ) ), fn ( $args ) => null === $info( $args ) ? null : (string) $info( $args )->get_asn()?->get_type() ),
			'ipinfo_is_vpn'        => self::boolean( $group, __( 'VPN', 'sugarcommerce' ), __( 'Yes when the address is a VPN exit. Business plan and above.', 'sugarcommerce' ), $privacy( 'vpn' ) ),
			'ipinfo_is_proxy'      => self::boolean( $group, __( 'Proxy', 'sugarcommerce' ), __( 'Yes when the address is a proxy. Business plan and above.', 'sugarcommerce' ), $privacy( 'proxy' ) ),
			'ipinfo_is_tor'        => self::boolean( $group, __( 'Tor', 'sugarcommerce' ), __( 'Yes when the address is a Tor exit node. Business plan and above.', 'sugarcommerce' ), $privacy( 'tor' ) ),
			'ipinfo_is_relay'      => self::boolean( $group, __( 'Privacy Relay', 'sugarcommerce' ), __( 'Yes for a privacy relay such as iCloud Private Relay -- mostly ordinary Apple users, so a soft signal.', 'sugarcommerce' ), $privacy( 'relay' ) ),
			'ipinfo_is_hosting'    => self::boolean( $group, __( 'Hosting/Datacenter', 'sugarcommerce' ), __( 'Yes when the address belongs to a hosting company or a data centre.', 'sugarcommerce' ), $privacy( 'hosting' ) ),
			'ipinfo_is_suspicious' => self::boolean(
				$group,
				__( 'Suspicious', 'sugarcommerce' ),
				__( 'Yes when the address is a VPN, a proxy, Tor or hosting. Relays are left out.', 'sugarcommerce' ),
				function ( array $args ) use ( $info ): ?bool {
					$privacy = $info( $args )?->get_privacy();

					return null === $privacy ? null : ( $privacy->is_vpn() || $privacy->is_proxy() || $privacy->is_tor() || $privacy->is_hosting() );
				}
			),
		);
	}

	/**
	 * AbuseIPDB's conditions.
	 *
	 * @param AbuseIPDB $client The client.
	 *
	 * @return array<string, array>
	 */
	private static function abuseipdb( AbuseIPDB $client ): array {
		$group = __( 'AbuseIPDB', 'sugarcommerce' );
		$check = function ( array $args ) use ( $client ): ?Providers\AbuseIPDB\Check {
			$ip     = self::ip( $args );
			$answer = '' === $ip ? null : self::answer( $client, 'ip', $ip, fn () => $client->check_ip( $ip ) );

			return null === $answer || is_wp_error( $answer ) ? null : $answer;
		};

		return array(
			'abuseipdb_confidence_score' => self::number( $group, __( 'Confidence Score', 'sugarcommerce' ), __( 'AbuseIPDB abuse confidence (0-100): 75 and over high, 90 and over very high.', 'sugarcommerce' ), fn ( $args ) => $check( $args )?->get_confidence_score(), 75 ),
			'abuseipdb_is_abusive'       => self::boolean( $group, __( 'Abusive', 'sugarcommerce' ), __( 'Yes when the confidence score is 75 or above.', 'sugarcommerce' ), fn ( $args ) => $check( $args )?->is_abusive( AbuseIPDB::ABUSIVE_SCORE ) ),
			'abuseipdb_total_reports'    => self::number( $group, __( 'Total Reports', 'sugarcommerce' ), __( 'How many reports there are on the address. The score weighs recent ones higher; this is the plain count.', 'sugarcommerce' ), fn ( $args ) => $check( $args )?->get_total_reports(), 5, false ),
			'abuseipdb_country'          => self::country( $group, fn ( $args ) => $check( $args )?->get_country_code() ),
			'abuseipdb_is_tor'           => self::boolean( $group, __( 'Tor', 'sugarcommerce' ), __( 'Yes when AbuseIPDB lists the address as a Tor exit node.', 'sugarcommerce' ), fn ( $args ) => $check( $args )?->is_tor() ),
			'abuseipdb_is_whitelisted'   => self::boolean( $group, __( 'Public Allowlist', 'sugarcommerce' ), __( 'Yes when the address is on AbuseIPDB\'s allowlist -- Google, Cloudflare and the like. "Is no" keeps a rule off their crawlers.', 'sugarcommerce' ), fn ( $args ) => $check( $args )?->is_whitelisted() ),
		);
	}

	/**
	 * The common conditions, for a provider of your own.
	 *
	 * @param Provider $provider The provider.
	 *
	 * @return array<string, array>
	 */
	private static function common( Provider $provider ): array {
		$id     = $provider->get_id();
		$group  = $provider->get_name();
		$result = fn ( array $args ): ?Result => self::result( $provider, $args );

		return array(
			"{$id}_risk_score" => self::number( $group, __( 'Risk Score', 'sugarcommerce' ), __( 'The service\'s risk score, 0 to 100.', 'sugarcommerce' ), fn ( $args ) => $result( $args )?->get_risk_score(), 75 ),
			"{$id}_is_proxy"   => self::boolean( $group, __( 'Proxy', 'sugarcommerce' ), '', fn ( $args ) => $result( $args )?->is_proxy() ),
			"{$id}_is_vpn"     => self::boolean( $group, __( 'VPN', 'sugarcommerce' ), '', fn ( $args ) => $result( $args )?->is_vpn() ),
			"{$id}_is_tor"     => self::boolean( $group, __( 'Tor', 'sugarcommerce' ), '', fn ( $args ) => $result( $args )?->is_tor() ),
			"{$id}_is_hosting" => self::boolean( $group, __( 'Hosting/Datacenter', 'sugarcommerce' ), '', fn ( $args ) => $result( $args )?->is_hosting() ),
			"{$id}_country"    => self::country( $group, fn ( $args ) => $result( $args )?->get_country_code() ),
		);
	}

	/**
	 * A provider's common answer for the rule's address, once per request.
	 *
	 * @param Provider $provider The provider.
	 * @param array    $args     The rule's arguments.
	 *
	 * @return Result|null Null when there is no address or no answer.
	 */
	private static function result( Provider $provider, array $args ): ?Result {
		$ip = self::ip( $args );

		if ( '' === $ip ) {
			return null;
		}

		$answer = self::answer( $provider, 'lookup', $ip, fn () => $provider->lookup( $ip ) );

		return $answer instanceof Result ? $answer : null;
	}

	/**
	 * ProxyCheck's answer for the rule's address, with the VPN operator, the
	 * network and the risk asked for.
	 *
	 * @param ProxyCheck $client The client.
	 * @param array      $args   The rule's arguments.
	 *
	 * @return ProxyCheckIP|null
	 */
	private static function proxycheck_check( ProxyCheck $client, array $args ): ?ProxyCheckIP {
		$result = self::result( $client, $args );
		$check  = $result?->get_response();

		return $check instanceof ProxyCheckIP ? $check : null;
	}

	/**
	 * Ask once per request.
	 *
	 * @param Provider $provider The provider.
	 * @param string   $kind     What kind of question.
	 * @param string   $subject  What it is about.
	 * @param callable $ask      Asks it.
	 *
	 * @return mixed|WP_Error
	 */
	private static function answer( Provider $provider, string $kind, string $subject, callable $ask ): mixed {
		$key = spl_object_id( $provider ) . "|{$kind}|" . strtolower( $subject );

		if ( ! array_key_exists( $key, self::$answers ) ) {
			self::$answers[ $key ] = $ask();
		}

		return self::$answers[ $key ];
	}

	/**
	 * Every VPN brand on the exit, lower case: the operator and those
	 * sharing its infrastructure.
	 *
	 * @param array $entry ProxyCheck's answer for the address.
	 *
	 * @return string[]
	 */
	private static function operator_names( array $entry ): array {
		$operator = $entry['operator'] ?? null;

		if ( ! is_array( $operator ) ) {
			return array();
		}

		$names = array_merge( array( $operator['name'] ?? '' ), (array) ( $operator['additional_operators'] ?? array() ) );

		return array_values( array_unique( array_filter( array_map( fn ( $name ) => is_scalar( $name ) ? strtolower( trim( (string) $name ) ) : '', $names ) ) ) );
	}

	/**
	 * A yes/no condition.
	 *
	 * @param string   $group       The group in the builder.
	 * @param string   $label       The label.
	 * @param string   $description What it means.
	 * @param callable $compare     Gives the answer, or null for none.
	 * @param string[] $required    Arguments without which it is skipped.
	 *
	 * @return array
	 */
	private static function boolean( string $group, string $label, string $description, callable $compare, array $required = array() ): array {
		return array(
			'label'         => $label,
			'group'         => $group,
			'type'          => 'boolean',
			'description'   => $description,
			'compare_value' => $compare,
			'required_args' => $required,
		);
	}

	/**
	 * A number condition.
	 *
	 * @param string   $group       The group.
	 * @param string   $label       The label.
	 * @param string   $description What it means.
	 * @param callable $compare     Gives the number, or null for none.
	 * @param int      $example     The placeholder.
	 * @param bool     $percent     Whether it is held to 0-100.
	 *
	 * @return array
	 */
	private static function number( string $group, string $label, string $description, callable $compare, int $example, bool $percent = true ): array {
		return array(
			'label'         => $label,
			'group'         => $group,
			'type'          => 'number',
			/* translators: %d: an example number. */
			'placeholder'   => sprintf( __( 'e.g. %d', 'sugarcommerce' ), $example ),
			'min'           => 0,
			'step'          => 1,
			'description'   => $description,
			'compare_value' => $compare,
			'required_args' => array(),
		) + ( $percent ? array( 'max' => 100 ) : array() );
	}

	/**
	 * A text condition.
	 *
	 * @param string   $group       The group.
	 * @param string   $label       The label.
	 * @param string   $description What it means.
	 * @param callable $compare     Gives the text, or null for none.
	 *
	 * @return array
	 */
	private static function text( string $group, string $label, string $description, callable $compare ): array {
		return array(
			'label'         => $label,
			'group'         => $group,
			'type'          => 'text',
			'description'   => $description,
			'compare_value' => $compare,
			'required_args' => array(),
		);
	}

	/**
	 * A condition matched against a typed list, exactly.
	 *
	 * @param string   $group       The group.
	 * @param string   $label       The label.
	 * @param string   $description What it means.
	 * @param callable $compare     Gives the value or values, or null for none.
	 *
	 * @return array
	 */
	private static function tags( string $group, string $label, string $description, callable $compare ): array {
		return array(
			'label'         => $label,
			'group'         => $group,
			'type'          => 'tags',
			'operators'     => Operators::tags_exact(),
			'description'   => $description,
			'compare_value' => $compare,
			'required_args' => array(),
		);
	}

	/**
	 * A condition matched against a list of choices.
	 *
	 * @param string         $group       The group.
	 * @param string         $label       The label.
	 * @param string         $description What it means.
	 * @param array|callable $options     The choices, as value and label.
	 * @param callable       $compare     Gives the value, or null for none.
	 *
	 * @return array
	 */
	private static function choice( string $group, string $label, string $description, array|callable $options, callable $compare ): array {
		return array(
			'label'         => $label,
			'group'         => $group,
			'type'          => 'select',
			'multiple'      => true,
			'options'       => $options,
			'operators'     => Operators::collection_any_none(),
			'description'   => $description,
			'compare_value' => $compare,
			'required_args' => array(),
		);
	}

	/**
	 * A country condition.
	 *
	 * @param string   $group   The group.
	 * @param callable $compare Gives the code, or null for none.
	 *
	 * @return array
	 */
	private static function country( string $group, callable $compare ): array {
		return self::choice(
			$group,
			__( 'Country', 'sugarcommerce' ),
			__( 'The country the address is in. Useful beside the billing country, or for a second opinion on the visitor\'s.', 'sugarcommerce' ),
			fn () => GeoOptions::get_country_options(),
			function ( array $args ) use ( $compare ): ?string {
				$code = $compare( $args );

				return null === $code ? null : strtoupper( (string) $code );
			}
		);
	}

	/**
	 * The continents, as choices.
	 *
	 * @return array<array{value: string, label: string}>
	 */
	private static function continents(): array {
		$options = array();

		foreach ( Countries::get_continent_codes() as $code => $name ) {
			$options[] = array(
				'value' => $code,
				'label' => $name,
			);
		}

		return $options;
	}

	/**
	 * Values as choices.
	 *
	 * @param string[] $values The values.
	 * @param string[] $labels Their labels, if not the values themselves.
	 *
	 * @return array<array{value: string, label: string}>
	 */
	private static function options( array $values, array $labels = array() ): array {
		$options = array();

		foreach ( array_values( $values ) as $i => $value ) {
			$options[] = array(
				'value' => $value,
				'label' => $labels[ $i ] ?? $value,
			);
		}

		return $options;
	}
}
