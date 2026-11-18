<?php
/**
 * IPQualityScore
 *
 * @package   SugarCommerce\IpLookup
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\IpLookup\Providers;

use DateTime;
use SugarCommerce\IpLookup\Providers\IPQualityScore\Response\CountryList;
use SugarCommerce\IpLookup\Providers\IPQualityScore\Response\CreditUsage;
use SugarCommerce\IpLookup\Providers\IPQualityScore\Response\Email;
use SugarCommerce\IpLookup\Providers\IPQualityScore\Response\EntryList;
use SugarCommerce\IpLookup\Providers\IPQualityScore\Response\FraudReport;
use SugarCommerce\IpLookup\Providers\IPQualityScore\Response\IP;
use SugarCommerce\IpLookup\Providers\IPQualityScore\Response\LeakCheck;
use SugarCommerce\IpLookup\Providers\IPQualityScore\Response\MalwareCheck;
use SugarCommerce\IpLookup\Providers\IPQualityScore\Response\Phone;
use SugarCommerce\IpLookup\Providers\IPQualityScore\Response\RequestList;
use SugarCommerce\IpLookup\Providers\IPQualityScore\Response\Transaction as TransactionResponse;
use SugarCommerce\IpLookup\Providers\IPQualityScore\Response\URL;
use SugarCommerce\IpLookup\Providers\IPQualityScore\Transaction;
use SugarCommerce\IpLookup\Result;
use SugarCommerce\IpLookup\Service;
use SugarCommerce\Network\IP as Address;
use SugarCommerce\Network\Request;
use WP_Error;

/**
 * Class IPQualityScore
 *
 * IPQualityScore (https://www.ipqualityscore.com/documentation): the
 * questions a checkout keeps asking, behind one key -- is this address a
 * proxy, is this inbox real, does this phone number exist, is this link or
 * file malicious -- and the account's own allow and block lists.
 *
 * Its strictness is a dial, 0 to 3: each step catches more fraud and more
 * innocent customers with it.
 *
 * @since 1.0.0
 */
class IPQualityScore extends Service {

	protected const ID = 'ipqualityscore';

	protected const NAME = 'IPQualityScore';

	/**
	 * The API.
	 */
	private const API_BASE = 'https://ipqualityscore.com/api/json/';

	/**
	 * The largest file the malware scanner takes: 100 MB.
	 */
	public const MAX_FILE_SIZE = 104857600;

	/**
	 * The kinds of allow and block list entry, and the values each takes.
	 * Null takes any value type.
	 */
	private const ENTRYLIST_TYPES = array(
		'proxy'         => array( 'ip', 'cidr', 'isp' ),
		'devicetracker' => array( 'deviceid', 'ip', 'cidr', 'isp' ),
		'mobiletracker' => array( 'deviceid', 'ip', 'cidr', 'isp' ),
		'email'         => array( 'email' ),
		'url'           => array( 'domain' ),
		'phone'         => array( 'phone' ),
		'custom'        => null,
	);

	/**
	 * How each endpoint is called. Every other endpoint is a POST to
	 * `{base}{endpoint}/{key}`.
	 *
	 * `value` is the parameter that goes into the path after the key,
	 * `type` one that goes before the key, `common` whether the strictness
	 * and the visitor's agent and language are sent along.
	 */
	private const ENDPOINTS = array(
		'ip'             => array(
			'method' => 'GET',
			'value'  => 'ip',
		),
		'phone'          => array(
			'method' => 'GET',
			'value'  => 'phone',
		),
		'url'            => array(
			'method' => 'GET',
			'value'  => 'url',
			'encode' => true,
		),
		'leaked'         => array(
			'method' => 'GET',
			'type'   => 'type',
			'value'  => 'value',
			'encode' => true,
		),
		'account'        => array( 'method' => 'GET' ),
		'requests'       => array(
			'method' => 'GET',
			'suffix' => '/list',
			'common' => false,
		),
		'allowlist/list' => array( 'method' => 'GET' ),
		'blocklist/list' => array( 'method' => 'GET' ),
	);

	/**
	 * How suspicious to be, 0 to 3.
	 *
	 * @var int
	 */
	private int $strictness = 0;

	/**
	 * Whether a public hotspot or a corporate gateway is let off.
	 *
	 * @var bool
	 */
	private bool $allow_public_access_points = false;

	/**
	 * Whether to score lightly, for fewer false positives.
	 *
	 * @var bool
	 */
	private bool $lighter_penalties = false;

	/**
	 * Build the client.
	 *
	 * @since 1.0.0
	 *
	 * @param string $api_key The key.
	 * @param array  $args    The settings every provider takes (`cache`,
	 *                        `cache_ttl`, `failure_ttl`), and `strictness`,
	 *                        `allow_public_access_points` and
	 *                        `lighter_penalties`.
	 */
	public function __construct( #[\SensitiveParameter] string $api_key = '', array $args = array() ) {
		parent::__construct( $api_key, $args );

		if ( isset( $args['strictness'] ) ) {
			$this->set_strictness( (int) $args['strictness'] );
		}

		if ( isset( $args['allow_public_access_points'] ) ) {
			$this->set_allow_public_access_points( (bool) $args['allow_public_access_points'] );
		}

		if ( isset( $args['lighter_penalties'] ) ) {
			$this->set_lighter_penalties( (bool) $args['lighter_penalties'] );
		}
	}

	/**
	 * How suspicious to be.
	 *
	 * @since 1.0.0
	 *
	 * @param int $strictness 0 to 3.
	 *
	 * @return static
	 */
	public function set_strictness( int $strictness ): static {
		$this->strictness = max( 0, min( 3, $strictness ) );

		return $this;
	}

	/**
	 * How suspicious it is, 0 to 3.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	public function get_strictness(): int {
		return $this->strictness;
	}

	/**
	 * Let off public hotspots and corporate gateways.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $allow Whether to.
	 *
	 * @return static
	 */
	public function set_allow_public_access_points( bool $allow ): static {
		$this->allow_public_access_points = $allow;

		return $this;
	}

	/**
	 * Score lightly, for fewer false positives.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $lighter Whether to.
	 *
	 * @return static
	 */
	public function set_lighter_penalties( bool $lighter ): static {
		$this->lighter_penalties = $lighter;

		return $this;
	}

	/**
	 * What IPQualityScore knows about an address.
	 *
	 * @since 1.0.0
	 *
	 * @param string $ip     The address.
	 * @param array  $params More of the API's parameters.
	 *
	 * @return IP|WP_Error
	 */
	public function check_ip( string $ip, array $params = array() ): IP|WP_Error {
		$ip = trim( $ip );

		if ( ! self::is_lookupable( $ip ) ) {
			return $this->invalid_ip( $ip );
		}

		return $this->cached( IP::class, 'ip_' . $ip, 'ip', array( 'ip' => $ip ) + $params );
	}

	/**
	 * Whether an email address is real, deliverable and safe.
	 *
	 * @since 1.0.0
	 *
	 * @param string $email  The address.
	 * @param array  $params More of the API's parameters.
	 *
	 * @return Email|WP_Error
	 */
	public function validate_email( string $email, array $params = array() ): Email|WP_Error {
		if ( ! filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
			/* translators: %s: the email address. */
			return $this->error( 'invalid_email', sprintf( __( 'Not an email address: %s', 'sugarcommerce' ), $email ) );
		}

		return $this->cached( Email::class, 'email_' . $email, 'email', array( 'email' => $email ) + $params );
	}

	/**
	 * Whether a phone number is real, and whose it is.
	 *
	 * @since 1.0.0
	 *
	 * @param string $phone  The number, in any format.
	 * @param array  $params More of the API's parameters: `country` (a list
	 *                       of likely countries), `strictness`.
	 *
	 * @return Phone|WP_Error
	 */
	public function validate_phone( string $phone, array $params = array() ): Phone|WP_Error {
		$phone = (string) preg_replace( '/[^0-9]/', '', $phone );

		if ( strlen( $phone ) < 10 ) {
			return $this->error( 'invalid_phone', __( 'A phone number has at least 10 digits.', 'sugarcommerce' ) );
		}

		return $this->cached( Phone::class, 'phone_' . $phone, 'phone', array( 'phone' => $phone ) + $params );
	}

	/**
	 * Whether an email address, username or password has turned up in a
	 * breach.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value  What to look for.
	 * @param string $type   `email`, `username` or `password`.
	 * @param array  $params More of the API's parameters.
	 *
	 * @return LeakCheck|WP_Error
	 */
	public function check_leaked_data( #[\SensitiveParameter] string $value, string $type = 'email', array $params = array() ): LeakCheck|WP_Error {
		if ( ! in_array( $type, array( 'email', 'password', 'username' ), true ) ) {
			return $this->error( 'invalid_type', __( 'A leak check is for an email, a username or a password.', 'sugarcommerce' ) );
		}

		if ( 'email' === $type && ! filter_var( $value, FILTER_VALIDATE_EMAIL ) ) {
			/* translators: %s: the email address. */
			return $this->error( 'invalid_email', sprintf( __( 'Not an email address: %s', 'sugarcommerce' ), $value ) );
		}

		if ( '' === $value ) {
			/* translators: %s: "username" or "password". */
			return $this->error( "invalid_{$type}", sprintf( __( 'The %s is empty.', 'sugarcommerce' ), $type ) );
		}

		// Hashed into the key, so a password is never part of one.
		return $this->cached(
			LeakCheck::class,
			"leak_{$type}_" . hash( 'sha256', $value ),
			'leaked',
			array(
				'type'  => $type,
				'value' => $value,
			) + $params
		);
	}

	/**
	 * Whether a URL is phishing, malware, parked or otherwise unsafe.
	 *
	 * @since 1.0.0
	 *
	 * @param string $url    The URL.
	 * @param array  $params More of the API's parameters.
	 *
	 * @return URL|WP_Error
	 */
	public function scan_url( string $url, array $params = array() ): URL|WP_Error {
		if ( ! filter_var( $url, FILTER_VALIDATE_URL ) ) {
			/* translators: %s: the URL. */
			return $this->error( 'invalid_url', sprintf( __( 'Not a URL: %s', 'sugarcommerce' ), $url ) );
		}

		return $this->cached( URL::class, 'url_' . $url, 'url', array( 'url' => $url ) + $params );
	}

	/**
	 * Scan a file on this server for malware.
	 *
	 * @since 1.0.0
	 *
	 * @param string $file_path The file. At most 100 MB.
	 * @param array  $params    More of the API's parameters.
	 *
	 * @return MalwareCheck|WP_Error
	 */
	public function scan_file_for_malware( string $file_path, array $params = array() ): MalwareCheck|WP_Error {
		if ( ! is_file( $file_path ) || ! is_readable( $file_path ) ) {
			/* translators: %s: the file's path. */
			return $this->error( 'invalid_file', sprintf( __( 'The file cannot be read: %s', 'sugarcommerce' ), $file_path ) );
		}

		if ( filesize( $file_path ) > self::MAX_FILE_SIZE ) {
			return $this->error( 'file_too_large', __( 'The file is over the 100 MB the scanner takes.', 'sugarcommerce' ) );
		}

		$data = $this->remember(
			'malware_file_' . hash_file( 'sha256', $file_path ) . md5( serialize( $params ) ),
			function () use ( $file_path, $params ) {
				$boundary = 'iplookup' . bin2hex( random_bytes( 12 ) );
				$body     = '';

				foreach ( $params as $name => $value ) {
					$body .= "--{$boundary}\r\nContent-Disposition: form-data; name=\"{$name}\"\r\n\r\n{$value}\r\n";
				}

				$body .= "--{$boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" . basename( $file_path ) . "\"\r\n"
					. "Content-Type: application/octet-stream\r\n\r\n"
					. (string) file_get_contents( $file_path ) // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- a local file, read whole to send it.
					. "\r\n--{$boundary}--\r\n";

				return $this->answer(
					$this->request(
						'POST',
						$this->endpoint_url( 'malware/scan' ),
						array(
							'headers' => array( 'Content-Type' => 'multipart/form-data; boundary=' . $boundary ),
							'body'    => $body,
							'timeout' => 60,
						)
					)
				);
			}
		);

		return is_wp_error( $data ) ? $data : new MalwareCheck( $data );
	}

	/**
	 * Whether a file with this SHA-256 is known malware.
	 *
	 * @since 1.0.0
	 *
	 * @param string $file_hash The file's SHA-256, in hex.
	 * @param array  $params    More of the API's parameters.
	 *
	 * @return MalwareCheck|WP_Error
	 */
	public function lookup_malware_hash( string $file_hash, array $params = array() ): MalwareCheck|WP_Error {
		if ( 1 !== preg_match( '/^[a-fA-F0-9]{64}$/', $file_hash ) ) {
			return $this->error( 'invalid_hash', __( 'Not a SHA-256 hash.', 'sugarcommerce' ) );
		}

		return $this->cached( MalwareCheck::class, 'malware_hash_' . $file_hash, 'malware/lookup', array( 'hash' => $file_hash ) + $params );
	}

	/**
	 * Scan a file somewhere else, by its URL, for malware.
	 *
	 * @since 1.0.0
	 *
	 * @param string $url    The file's URL.
	 * @param array  $params More of the API's parameters.
	 *
	 * @return MalwareCheck|WP_Error
	 */
	public function scan_remote_file( string $url, array $params = array() ): MalwareCheck|WP_Error {
		if ( ! filter_var( $url, FILTER_VALIDATE_URL ) ) {
			/* translators: %s: the URL. */
			return $this->error( 'invalid_url', sprintf( __( 'Not a URL: %s', 'sugarcommerce' ), $url ) );
		}

		return $this->cached( MalwareCheck::class, 'malware_url_' . $url, 'malware/scan', array( 'url' => $url ) + $params );
	}

	/**
	 * Score a whole transaction: the address, the person, the card, the
	 * billing and shipping addresses. Never cached.
	 *
	 * @since 1.0.0
	 *
	 * @param array|Transaction $transaction The fields, or a Transaction
	 *                                       built up with its setters.
	 *                                       `ip_address` is required.
	 *
	 * @return TransactionResponse|WP_Error
	 */
	public function validate_transaction( array|Transaction $transaction ): TransactionResponse|WP_Error {
		$data = $transaction instanceof Transaction ? $transaction->get_data() : $transaction;

		if ( ! isset( $data['ip_address'] ) ) {
			/* translators: %s: the missing field's name. */
			return $this->error( 'missing_field', sprintf( __( 'Missing required field: %s', 'sugarcommerce' ), 'ip_address' ) );
		}

		$answer = $this->call( 'transaction', $data );

		return is_wp_error( $answer ) ? $answer : new TransactionResponse( $answer );
	}

	/**
	 * The account's credits and what has used them. Cached for at most five
	 * minutes.
	 *
	 * @since 1.0.0
	 *
	 * @param array $params More of the API's parameters.
	 *
	 * @return CreditUsage|WP_Error
	 */
	public function get_credit_usage( array $params = array() ): CreditUsage|WP_Error {
		return $this->cached( CreditUsage::class, 'credit_usage', 'account', $params, min( 300, $this->get_cache_ttl() ) );
	}

	/**
	 * Report fraud, so IPQualityScore scores it higher next time.
	 *
	 * @since 1.0.0
	 *
	 * @param array $data   One of `ip`, `email`, `request_id`, or `phone`
	 *                      with its `country`.
	 * @param array $params More of the API's parameters.
	 *
	 * @return FraudReport|WP_Error
	 */
	public function report_fraud( array $data, array $params = array() ): FraudReport|WP_Error {
		if ( empty( $data['ip'] ) && empty( $data['email'] ) && empty( $data['request_id'] ) && empty( $data['phone'] ) ) {
			return $this->error( 'missing_parameter', __( 'A report needs an ip, an email, a request_id or a phone.', 'sugarcommerce' ) );
		}

		if ( isset( $data['ip'] ) && ! Address::is_valid( (string) $data['ip'] ) ) {
			/* translators: %s: the IP address. */
			return $this->error( 'invalid_ip', sprintf( __( 'Not an IP address: %s', 'sugarcommerce' ), $data['ip'] ) );
		}

		if ( isset( $data['email'] ) && ! filter_var( $data['email'], FILTER_VALIDATE_EMAIL ) ) {
			/* translators: %s: the email address. */
			return $this->error( 'invalid_email', sprintf( __( 'Not an email address: %s', 'sugarcommerce' ), $data['email'] ) );
		}

		if ( isset( $data['phone'] ) ) {
			if ( empty( $data['country'] ) ) {
				return $this->error( 'missing_country', __( 'A phone number is reported with its country.', 'sugarcommerce' ) );
			}

			if ( 1 !== preg_match( '/^\+?[\d\s-]{9,20}$/', (string) $data['phone'] ) ) {
				/* translators: %s: the phone number. */
				return $this->error( 'invalid_phone', sprintf( __( 'Not a phone number: %s', 'sugarcommerce' ), $data['phone'] ) );
			}

			if ( 2 === strlen( (string) $data['country'] ) && 1 !== preg_match( '/^[A-Za-z]{2}$/', (string) $data['country'] ) ) {
				/* translators: %s: the country code. */
				return $this->error( 'invalid_country', sprintf( __( 'Not a country code: %s', 'sugarcommerce' ), $data['country'] ) );
			}
		}

		$answer = $this->call( 'report', array_merge( $data, $params ) );

		return is_wp_error( $answer ) ? $answer : new FraudReport( $answer );
	}

	/**
	 * Report an address.
	 *
	 * @since 1.0.0
	 *
	 * @param string $ip     The address.
	 * @param array  $params More of the API's parameters.
	 *
	 * @return FraudReport|WP_Error
	 */
	public function report_ip( string $ip, array $params = array() ): FraudReport|WP_Error {
		return $this->report_fraud( array( 'ip' => $ip ), $params );
	}

	/**
	 * Report an email address.
	 *
	 * @since 1.0.0
	 *
	 * @param string $email  The address.
	 * @param array  $params More of the API's parameters.
	 *
	 * @return FraudReport|WP_Error
	 */
	public function report_email( string $email, array $params = array() ): FraudReport|WP_Error {
		return $this->report_fraud( array( 'email' => $email ), $params );
	}

	/**
	 * Report a phone number.
	 *
	 * @since 1.0.0
	 *
	 * @param string $phone   The number.
	 * @param string $country Its country, as a code or a name.
	 * @param array  $params  More of the API's parameters.
	 *
	 * @return FraudReport|WP_Error
	 */
	public function report_phone( string $phone, string $country, array $params = array() ): FraudReport|WP_Error {
		return $this->report_fraud(
			array(
				'phone'   => $phone,
				'country' => $country,
			),
			$params
		);
	}

	/**
	 * Report an earlier request as fraud, by its id.
	 *
	 * @since 1.0.0
	 *
	 * @param string $request_id The request's id.
	 * @param array  $params     More of the API's parameters.
	 *
	 * @return FraudReport|WP_Error
	 */
	public function report_request( string $request_id, array $params = array() ): FraudReport|WP_Error {
		return $this->report_fraud( array( 'request_id' => $request_id ), $params );
	}

	/**
	 * Earlier requests, a page at a time. Cached for at most five minutes.
	 *
	 * @since 1.0.0
	 *
	 * @param string $type   `proxy`, `email`, `devicetracker` or `mobiletracker`.
	 * @param array  $params `start_date` and `stop_date` (Y-m-d, the last 30
	 *                       days by default), `ip_address`, `device_id`,
	 *                       `page`, and any tracking variables.
	 *
	 * @return RequestList|WP_Error
	 */
	public function get_request_list( string $type, array $params = array() ): RequestList|WP_Error {
		if ( ! in_array( $type, array( 'proxy', 'email', 'devicetracker', 'mobiletracker' ), true ) ) {
			return $this->error( 'invalid_type', __( 'Requests are listed for proxy, email, devicetracker or mobiletracker.', 'sugarcommerce' ) );
		}

		$params += array(
			'start_date' => gmdate( 'Y-m-d', time() - 30 * DAY_IN_SECONDS ),
			'stop_date'  => gmdate( 'Y-m-d' ),
		);

		foreach ( array( 'start_date', 'stop_date' ) as $field ) {
			$date = DateTime::createFromFormat( '!Y-m-d', (string) $params[ $field ] );

			if ( ! $date || $date->format( 'Y-m-d' ) !== $params[ $field ] ) {
				/* translators: %s: the date field's name. */
				return $this->error( 'invalid_date', sprintf( __( '%s is not a Y-m-d date.', 'sugarcommerce' ), $field ) );
			}
		}

		if ( isset( $params['ip_address'] ) && ! Address::is_valid( (string) $params['ip_address'] ) ) {
			/* translators: %s: the IP address. */
			return $this->error( 'invalid_ip', sprintf( __( 'Not an IP address: %s', 'sugarcommerce' ), $params['ip_address'] ) );
		}

		return $this->cached( RequestList::class, 'request_list_' . $type, 'requests', array( 'type' => $type ) + $params, min( 300, $this->get_cache_ttl() ) );
	}

	/**
	 * Every country IPQualityScore knows, with its code. Needs no key, and is
	 * kept for a day.
	 *
	 * @since 1.0.0
	 *
	 * @param bool $raw The plain-text list, instead of a CountryList.
	 *
	 * @return CountryList|string|WP_Error
	 */
	public function get_country_list( bool $raw = false ): CountryList|string|WP_Error {
		$data = $this->remember(
			'countries_' . ( $raw ? 'raw' : 'json' ),
			function () use ( $raw ) {
				$response = $this->request(
					'GET',
					'https://www.ipqualityscore.com/api/countries/' . ( $raw ? 'raw' : 'json' ),
					array( 'headers' => array( 'Accept' => $raw ? 'text/plain' : 'application/json' ) )
				);

				if ( $raw && ! is_wp_error( $response ) && 200 === $response['status'] ) {
					return $response['body'];
				}

				return $this->json( $response );
			},
			DAY_IN_SECONDS
		);

		if ( is_wp_error( $data ) || is_string( $data ) ) {
			return $data;
		}

		return new CountryList( $data );
	}

	/**
	 * The account's allowlist.
	 *
	 * @since 1.0.0
	 *
	 * @return EntryList|WP_Error
	 */
	public function get_allowlist_entries(): EntryList|WP_Error {
		return $this->list_call( 'allowlist/list' );
	}

	/**
	 * Add to the account's allowlist.
	 *
	 * @since 1.0.0
	 *
	 * @param string      $value      What to allow.
	 * @param string      $type       Which API: `proxy`, `url`, `email`, `phone`, `mobiletracker`, `devicetracker`, `custom`.
	 * @param string      $value_type What the value is: `ip`, `cidr`, `isp`, `email`, `domain`, `phone`, `deviceid`.
	 * @param string|null $reason     Why.
	 *
	 * @return EntryList|WP_Error
	 */
	public function create_allowlist_entry( string $value, string $type, string $value_type, ?string $reason = null ): EntryList|WP_Error {
		return $this->list_entry( 'allowlist', 'create', $value, $type, $value_type, $reason );
	}

	/**
	 * Remove from the account's allowlist.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value      What to remove.
	 * @param string $type       Which API.
	 * @param string $value_type What the value is.
	 *
	 * @return EntryList|WP_Error
	 */
	public function delete_allowlist_entry( string $value, string $type, string $value_type ): EntryList|WP_Error {
		return $this->list_entry( 'allowlist', 'delete', $value, $type, $value_type );
	}

	/**
	 * The account's blocklist.
	 *
	 * @since 1.0.0
	 *
	 * @return EntryList|WP_Error
	 */
	public function get_blocklist_entries(): EntryList|WP_Error {
		return $this->list_call( 'blocklist/list' );
	}

	/**
	 * Add to the account's blocklist.
	 *
	 * @since 1.0.0
	 *
	 * @param string      $value      What to block.
	 * @param string      $type       Which API.
	 * @param string      $value_type What the value is.
	 * @param string|null $reason     Why.
	 *
	 * @return EntryList|WP_Error
	 */
	public function create_blocklist_entry( string $value, string $type, string $value_type, ?string $reason = null ): EntryList|WP_Error {
		return $this->list_entry( 'blocklist', 'create', $value, $type, $value_type, $reason );
	}

	/**
	 * Remove from the account's blocklist.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value      What to remove.
	 * @param string $type       Which API.
	 * @param string $value_type What the value is.
	 *
	 * @return EntryList|WP_Error
	 */
	public function delete_blocklist_entry( string $value, string $type, string $value_type ): EntryList|WP_Error {
		return $this->list_entry( 'blocklist', 'delete', $value, $type, $value_type );
	}

	/**
	 * Ask about an address, answered the common way.
	 *
	 * @since 1.0.0
	 *
	 * @param string $ip The address.
	 *
	 * @return Result|WP_Error
	 */
	public function lookup( string $ip ): Result|WP_Error {
		$check = $this->check_ip( $ip );

		if ( is_wp_error( $check ) ) {
			return $check;
		}

		$connection = $check->get_connection_type();

		return new Result(
			self::ID,
			trim( $ip ),
			array(
				'risk_score'      => $check->get_fraud_score(),
				'is_proxy'        => $check->is_proxy(),
				'is_vpn'          => $check->is_vpn(),
				'is_tor'          => $check->is_tor(),
				'is_bot'          => $check->is_bot(),
				'is_abusive'      => $check->has_recent_abuse(),
				'is_hosting'      => null === $connection ? null : 'datacenter' === strtolower( str_replace( ' ', '', $connection ) ),
				'country_code'    => $check->get_country_code(),
				'region'          => $check->get_region(),
				'city'            => $check->get_city(),
				'postal_code'     => $check->get_zip_code(),
				'latitude'        => $check->get_latitude(),
				'longitude'       => $check->get_longitude(),
				'timezone'        => $check->get_timezone(),
				'asn'             => $check->get_asn(),
				'isp'             => $check->get_isp(),
				'organisation'    => $check->get_organization(),
				'connection_type' => $connection,
			),
			$check
		);
	}

	/**
	 * Ask an endpoint, through the cache, and wrap the answer.
	 *
	 * @param class-string $response   The response class.
	 * @param string       $identifier What is asked.
	 * @param string       $endpoint   The endpoint.
	 * @param array        $params     Its parameters.
	 * @param int|null     $ttl        Seconds to keep it, if not the cache lifetime.
	 *
	 * @return object|WP_Error
	 */
	private function cached( string $response, string $identifier, string $endpoint, array $params, ?int $ttl = null ): object {
		$data = $this->remember( $identifier . '|' . md5( serialize( $params ) ), fn () => $this->call( $endpoint, $params ), $ttl );

		return is_wp_error( $data ) ? $data : new $response( $data );
	}

	/**
	 * Read one of the account's lists.
	 *
	 * @param string $endpoint The list's endpoint.
	 *
	 * @return EntryList|WP_Error
	 */
	private function list_call( string $endpoint ): EntryList|WP_Error {
		$answer = $this->call( $endpoint );

		return is_wp_error( $answer ) ? $answer : new EntryList( $answer );
	}

	/**
	 * Add to or remove from one of the account's lists.
	 *
	 * @param string      $list       `allowlist` or `blocklist`.
	 * @param string      $action     `create` or `delete`.
	 * @param string      $value      The value.
	 * @param string      $type       Which API.
	 * @param string      $value_type What the value is.
	 * @param string|null $reason     Why, when adding.
	 *
	 * @return EntryList|WP_Error
	 */
	private function list_entry( string $list, string $action, string $value, string $type, string $value_type, ?string $reason = null ): EntryList|WP_Error {
		if ( ! array_key_exists( $type, self::ENTRYLIST_TYPES ) ) {
			return $this->error(
				'invalid_type',
				sprintf(
					/* translators: 1: allowlist or blocklist, 2: the types it takes. */
					__( 'A %1$s entry is one of: %2$s', 'sugarcommerce' ),
					$list,
					implode( ', ', array_keys( self::ENTRYLIST_TYPES ) )
				)
			);
		}

		if ( null !== self::ENTRYLIST_TYPES[ $type ] && ! in_array( $value_type, self::ENTRYLIST_TYPES[ $type ], true ) ) {
			return $this->error(
				'invalid_value_type',
				sprintf(
					/* translators: 1: the entry type, 2: the value types it takes. */
					__( 'A %1$s entry is one of: %2$s', 'sugarcommerce' ),
					$type,
					implode( ', ', self::ENTRYLIST_TYPES[ $type ] )
				)
			);
		}

		if ( 'create' === $action && ! self::is_list_value( $value, $value_type ) ) {
			/* translators: %s: the value type. */
			return $this->error( 'invalid_value', sprintf( __( 'Not a valid %s.', 'sugarcommerce' ), $value_type ) );
		}

		$params = array(
			'value'      => $value,
			'type'       => $type,
			'value_type' => $value_type,
		);

		if ( null !== $reason ) {
			$params['reason'] = $reason;
		}

		$answer = $this->call( "{$list}/{$action}", $params );

		return is_wp_error( $answer ) ? $answer : new EntryList( $answer );
	}

	/**
	 * Whether a list value is the kind it says it is.
	 *
	 * @param string $value      The value.
	 * @param string $value_type What it should be.
	 *
	 * @return bool
	 */
	private static function is_list_value( string $value, string $value_type ): bool {
		return match ( $value_type ) {
			'ip'              => Address::is_valid( $value ),
			'cidr'            => Address::is_valid_range( $value ) && str_contains( $value, '/' ),
			'email'           => false !== filter_var( $value, FILTER_VALIDATE_EMAIL ),
			'domain'          => false !== filter_var( $value, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME ),
			'phone'           => 1 === preg_match( '/^\+?[\d\s-]{9,20}$/', $value ),
			'isp', 'deviceid' => '' !== trim( $value ),
			default           => true,
		};
	}

	/**
	 * The URL of an endpoint, with the key in it.
	 *
	 * @param string $endpoint The endpoint.
	 *
	 * @return string
	 */
	private function endpoint_url( string $endpoint ): string {
		return self::API_BASE . $endpoint . '/' . rawurlencode( $this->api_key );
	}

	/**
	 * Call an endpoint.
	 *
	 * @param string $endpoint The endpoint.
	 * @param array  $params   Its parameters.
	 *
	 * @return array|WP_Error The decoded answer.
	 */
	private function call( string $endpoint, array $params = array() ): array|WP_Error {
		$config = self::ENDPOINTS[ $endpoint ] ?? array( 'method' => 'POST' );

		if ( $config['common'] ?? true ) {
			$params = array_merge(
				array(
					'strictness'                 => $this->strictness,
					'user_agent'                 => Request::agent(),
					'user_language'              => self::header( 'HTTP_ACCEPT_LANGUAGE' ),
					'allow_public_access_points' => $this->allow_public_access_points,
					'lighter_penalties'          => $this->lighter_penalties,
					'fast'                       => false,
				),
				$params
			);
		}

		$url = self::API_BASE . $endpoint;

		if ( isset( $config['type'] ) ) {
			$url .= '/' . rawurlencode( (string) ( $params[ $config['type'] ] ?? '' ) );
			unset( $params[ $config['type'] ] );
		}

		$url .= '/' . rawurlencode( $this->api_key );

		if ( isset( $config['value'] ) ) {
			$value = (string) ( $params[ $config['value'] ] ?? '' );
			$url  .= '/' . ( empty( $config['encode'] ) ? $value : rawurlencode( $value ) );
			unset( $params[ $config['value'] ] );
		}

		$url .= $config['suffix'] ?? '';

		$args = array();

		if ( 'GET' === $config['method'] ) {
			$url .= empty( $params ) ? '' : '?' . http_build_query( $params );
		} else {
			$args['body'] = $params;
		}

		return $this->answer( $this->request( $config['method'], $url, $args ) );
	}

	/**
	 * Read an answer: IPQualityScore says 200 even when it refuses, and puts
	 * the refusal in `success` and `message`.
	 *
	 * @param array|WP_Error $response What request() returned.
	 *
	 * @return array|WP_Error
	 */
	private function answer( array|WP_Error $response ): array|WP_Error {
		$data = $this->json( $response );

		if ( is_wp_error( $data ) ) {
			return $data;
		}

		if ( isset( $data['errors'] ) && array() !== $data['errors'] ) {
			return $this->error( 'api_error', is_array( $data['errors'] ) ? implode( ' ', array_map( 'strval', $data['errors'] ) ) : (string) $data['errors'] );
		}

		if ( false === ( $data['success'] ?? null ) ) {
			return $this->error( 'api_error', (string) ( $data['message'] ?? __( 'IPQualityScore refused the request.', 'sugarcommerce' ) ) );
		}

		return $data;
	}

	/**
	 * A request header to pass on, unslashed and cleaned.
	 *
	 * @param string $key The `$_SERVER` key.
	 *
	 * @return string
	 */
	private static function header( string $key ): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- unslashed and cleaned on the next line.
		$value = $_SERVER[ $key ] ?? '';

		return is_string( $value ) ? sanitize_text_field( wp_unslash( $value ) ) : '';
	}
}
