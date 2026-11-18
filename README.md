# IP Lookup

Ask a fraud or location service about an IP address from WordPress, and get
the same answer back whichever service it was.

## What it does

AbuseIPDB, IPinfo, IPQualityScore, ProxyCheck and MaxMind minFraud each
answer "who is behind this address?" in their own shape, with their own idea
of a score and their own way of saying it went wrong. This gives each one a
client on the WordPress HTTP API, with every endpoint it had, and one
`lookup()` that brings the answer down to a common `Result`: risk, proxy,
VPN, Tor, relay, hosting, country and network. A check written against the
result keeps working when the service behind it changes.

Answers are cached. Failures are cached too, for a minute, because the
alternative is that an outage or a spent quota costs every visitor on the
checkout a full timeout. And an address that is not on the public internet
-- a private range, loopback, a misread proxy header -- is refused before
any request, so it costs no quota.

For a shop owner, each service's answers are also conditions in a
sugarcommerce/conditions rule builder.

## Features

* Ask five services about an address and read one answer: `lookup( $ip )`
* Know when a service did not say, rather than reading silence as "no"
* Fall back to a second service only when the first fails
* Use every endpoint each service has: emails, phones, URLs, files, transactions, batches, the account's own lists and usage
* Cache answers and remember failures, per key, with the lifetimes you choose
* Give owners rules like "Proxy is yes" or "VPN Operator is any of Mullvad", under the ids wp-conditions used

## Installation

```bash
composer require sugarcommerce/ip-lookup
```

## Quick start

Hold an order for review when the address hides who is behind it:

```php
use SugarCommerce\IpLookup\Providers\ProxyCheck;

$result = ( new ProxyCheck( $key ) )->lookup( $order->ip );

if ( is_wp_error( $result ) ) {
	return; // Let it through rather than lose a sale to somebody else's outage.
}

if ( $result->is_anonymous() || $result->is_high_risk( 80 ) ) {
	$order->hold( sprintf( 'ProxyCheck: risk %d, %s', $result->get_risk_score(), $result->get_country_code() ) );
}
```

## The providers

Each is a client for its whole API, and a `Provider` for the common answer.

| Class | Key | Common answer |
|---|---|---|
| `Providers\AbuseIPDB` | the API key | abuse confidence as risk, abusive at 75, Tor, hosting from the usage type |
| `Providers\IPInfo` | a token, or none for the free allowance | location and network; proxy, VPN, Tor, relay and hosting on the Business plan |
| `Providers\IPQualityScore` | the API key | fraud score, proxy, VPN, Tor, bot, recent abuse, location, network |
| `Providers\ProxyCheck` | the API key, or none for the free allowance | risk, proxy, VPN, Tor, hosting, location, network |
| `Providers\MinFraud` | the account id and the licence key | the address's own risk |

Every client takes its settings as an array, and has setters for them:

```php
new IPQualityScore( $key, array(
	'cache'       => true,   // set_cache_enabled()
	'cache_ttl'   => 3600,   // set_cache_ttl(); ProxyCheck and minFraud default to 600
	'failure_ttl' => 60,     // set_failure_ttl(); 0 retries every time
	'strictness'  => 1,      // IPQualityScore only: 0 to 3
) );

new AbuseIPDB( $key, array( 'max_age_days' => 30 ) );
new MinFraud( $account_id, $licence_key );
```

`clear_cache( $what )` forgets one answer, `clear_cache()` every answer that
provider kept -- with a persistent object cache too, where the answers are
not in the options table: it starts a new generation of cache keys (an
option named `iplookup_{id}_generation`), so nothing kept before is found again. Errors are `WP_Error`s whose codes start with the provider's
id: `proxycheck_api_error`, `ipinfo_invalid_ip`, `abuseipdb_recent_failure`.

## The common answer

```php
$result->get_risk_score();    // 0-100, or null
$result->is_high_risk( 75 );  // at or above, or null without a score
$result->is_proxy();          // and is_vpn(), is_tor(), is_relay(), is_hosting(), is_bot(), is_abusive()
$result->is_anonymous();      // proxy, VPN or Tor
$result->is_suspicious();     // anonymous, or a data centre
$result->get_country_code();  // and get_region(), get_city(), get_postal_code(), get_continent_code(), is_eu()
$result->get_latitude();      // and get_longitude(), get_timezone()
$result->get_asn();           // always "AS15169", however the service wrote it
$result->get_isp();           // and get_organisation(), get_connection_type()
$result->get_response();      // the provider's own response, with everything else it said
$result->to_array();
```

Every answer can be null, and null means the service did not say. IPinfo
has no risk score, AbuseIPDB knows nothing about VPNs, and IPinfo below the
Business plan says nothing about privacy at all. `is_anonymous()` is true on
any yes, false only when the service answered no to all three, and null
when it said nothing.

A score means something slightly different to each service: AbuseIPDB's
abuse confidence, IPQualityScore's fraud score, ProxyCheck's risk,
minFraud's address risk. Compare a score with the same service's
thresholds, not another's.

## More than one service

```php
use SugarCommerce\IpLookup\Lookup;

$lookup = new Lookup( new ProxyCheck( $key ), new IPInfo( $token ) );

$result  = $lookup->first( $ip );  // IPinfo is asked only when ProxyCheck fails
$answers = $lookup->all( $ip );    // [ 'proxycheck' => Result|WP_Error, 'ipinfo' => ... ]
```

Services disagree on the long tail; asking two and acting when both agree is
how precision is bought. A `Lookup` keeps each answer for the rest of the
request, failures included.

A service of your own implements `Provider`: `get_id()`, `get_name()` and
`lookup( $ip ): Result|WP_Error`. Extending `Service` gives it the key, the
cache and the failure memory.

## Everything else each service does

```php
$ipqs->validate_email( $email );               // ->is_disposable(), ->is_leaked(), ->get_deliverability()
$ipqs->validate_phone( $phone );               // ->is_voip(), ->get_carrier(), ->get_line_type()
$ipqs->check_leaked_data( $password, 'password' );
$ipqs->scan_url( $url );                       // ->is_phishing(), ->is_malware()
$ipqs->scan_file_for_malware( $path );         // sent as multipart, up to 100 MB
$ipqs->validate_transaction( ( new Transaction() )->set_ip_address( $ip )->set_billing( $billing ) );
$ipqs->report_ip( $ip );                       // and report_email(), report_phone(), report_request()
$ipqs->create_blocklist_entry( '203.0.113.0/24', 'proxy', 'cidr', 'chargebacks' );
$ipqs->get_credit_usage();                     // cached five minutes at most

$proxycheck->check_email( $email, true );      // true sends only the domain
$proxycheck->check_ips( $ips );                // a batch: 100 without a key, 1,000 with
$proxycheck->set_blocked_countries( array( 'RU' ) )->set_allowed_countries( array( 'GB' ) );
$proxycheck->get_usage();                      // the dashboard API: usage, detections, tags, queries
$proxycheck->add_to_blacklist( $ips );         // and the whitelist and CORS origins

$ipinfo->get_batch_info( $ips );               // cached ones are not asked again
$ipinfo->get_field( $ip, 'country' );          // plain text

$minfraud->check_score( array( 'device' => array( 'ip_address' => $ip ), 'email' => array( 'address' => $email ) ) );
```

ProxyCheck adds a verdict to every answer: `should_block()` is true for a
proxy or a VPN, a risk over 70, or a blocked country, and false again for an
allowed one. The verdict is worked out as the answer is read, so changing
the countries takes effect at once, without a new request.

## Rules a shop owner builds

With sugarcommerce/conditions, register the services' conditions into a set,
the clients already holding their keys:

```php
use SugarCommerce\IpLookup\Conditions;

Conditions::register( 'fraud_rule', new ProxyCheck( $key ), new IPQualityScore( $other_key ) );
```

The ids are wp-conditions' own -- `proxycheck_is_vpn`, `ipqs_fraud_score`,
`ipinfo_is_hosting`, `abuseipdb_confidence_score` and the rest -- so rules
saved against them keep working. minFraud adds `minfraud_ip_risk`; a provider
of your own gets `{id}_risk_score`, `{id}_is_proxy`, `{id}_is_vpn`,
`{id}_is_tor`, `{id}_is_hosting` and `{id}_country`.
`Conditions::definitions( $client )` returns them without registering.

The address is the `ip` argument, or `ip_address`, or what the conditions
library resolves -- its `ip` provider, else `REMOTE_ADDR`. Email conditions
need `email`. A lookup that fails is no answer: the condition gives null and
the rule does not match, so "VPN is no" cannot pass because the service was
down. Each answer is asked for once per request, however many conditions
read it.

## Moving from arraypress/wp-*

This library is `wp-abuseipdb`, `wp-ipinfo`, `wp-ipqualityscore`,
`wp-proxycheck` and `wp-maxmind-minfraud` in one, with the service
conditions wp-conditions had.

| Was | Now |
|---|---|
| `ArrayPress\AbuseIPDB\Client` | `SugarCommerce\IpLookup\Providers\AbuseIPDB` |
| `ArrayPress\AbuseIPDB\Response\Check` | `Providers\AbuseIPDB\Check` |
| `ArrayPress\IPInfo\Client` | `Providers\IPInfo` |
| `ArrayPress\IPInfo\Response` | `Providers\IPInfo\Response` |
| `ArrayPress\IPInfo\Info\{ASN, Company, Privacy, Abuse, Domains}` | `Providers\IPInfo\{...}` |
| `ArrayPress\IPQualityScore\Client` | `Providers\IPQualityScore` |
| `ArrayPress\IPQualityScore\Transaction` | `Providers\IPQualityScore\Transaction` |
| `ArrayPress\IPQualityScore\Response\*` | `Providers\IPQualityScore\Response\*` |
| `ArrayPress\ProxyCheck\Client` (with the `Parameters` and `Dashboard` traits) | `Providers\ProxyCheck` |
| `ArrayPress\ProxyCheck\Response\Client\{IP, DisposableEmail, Base}` | `Providers\ProxyCheck\Response\{...}` |
| `ArrayPress\ProxyCheck\Response\Dashboard\*` | `Providers\ProxyCheck\Response\Dashboard\*` |
| `ArrayPress\MaxMind\MinFraud\Client` | `Providers\MinFraud` |
| `ArrayPress\MaxMind\MinFraud\Response\Score` | `Providers\MinFraud\Score` |
| `ArrayPress\Conditions\Conditions\Services\*`, `ArrayPress\Conditions\Clients\*` | `Conditions::register( $set, ...$clients )` |

Building a client:

| Was | Now |
|---|---|
| `new AbuseIPDB\Client( $key, [ 'cache_enabled' => …, 'cache_ttl' => …, 'cache_prefix' => …, 'failure_ttl' => …, 'max_age_days' => … ] )` | `new AbuseIPDB( $key, [ 'cache' => …, 'cache_ttl' => …, 'failure_ttl' => …, 'max_age_days' => … ] )` |
| `new IPInfo\Client( $key, $enable_cache, $expiration )` | `new IPInfo( $key, [ 'cache' => $enable_cache, 'cache_ttl' => $expiration ] )` |
| `new IPQualityScore\Client( $key, $enable_cache, $expiration )` | `new IPQualityScore( $key, [ 'cache' => …, 'cache_ttl' => … ] )` |
| `new ProxyCheck\Client( $key, $enable_cache, $expiration, $prefix )` | `new ProxyCheck( $key, [ 'cache' => …, 'cache_ttl' => … ] )` |
| `new MinFraud\Client( $account, $licence, [ 'cache_enabled', 'cache_ttl', 'cache_prefix' ] )` | `new MinFraud( $account, $licence, [ 'cache' => …, 'cache_ttl' => … ] )` |
| `set_cache_expiration()`, `get_cache_expiration()` | `set_cache_ttl()`, `get_cache_ttl()` |
| `set_cache_prefix()`, `get_cache_prefix()`, `cache_prefix` | gone: every transient starts `iplookup_{id}_` |
| `get_cache_settings()` | `is_cache_enabled()`, `get_cache_ttl()`, `get_failure_ttl()` |

Reading an answer:

| Was | Now |
|---|---|
| `Check::to_array()`, `Score::to_array()` | unchanged |
| IPinfo `Response::get_all()`, ProxyCheck `IP::get_all()` | `to_array()` |
| IPQualityScore `get_raw_data()`, ProxyCheck dashboard `get_raw_data()` | `to_array()` |
| IPinfo `$response->all`, IPQualityScore `$response->field` | `$response->field`, or `get( 'field' )` |
| IPinfo `Response::get_continent()` (a `Continent`) | an array: `[ 'code' => 'EU', 'name' => 'Europe' ]` -- ProxyCheck's shape |
| IPinfo `Response::get_country_flag()` (a `CountryFlag`) | the emoji |
| IPinfo `Response::get_country_currency()` (a `CountryCurrency`) | `SugarCommerce\Money\Currencies::for_country( $response->get_country() )` |
| IPinfo `Utils\Locations::*` | `SugarCommerce\Geo\Countries` (names, continents, EU, flags) |
| IPinfo `Utils\IP::is_valid_for_lookup( $ip )`, `is_bogon()` | `Service::is_lookupable( $ip )`, `! SugarCommerce\Network\IP::is_public( $ip )` |
| IPinfo `Utils\IP::is_valid()`, `is_ipv4()`, `is_ipv6()`, `in_range()` | `SugarCommerce\Network\IP::is_valid()`, `is_valid_ipv4()`, `is_valid_ipv6()`, `is_in_range()` |
| IPinfo `Utils\IP::get_bogon_networks()` | gone: sugarcommerce/network keeps the ranges `is_public()` refuses |
| ProxyCheck `Dashboard::manage_list()` (protected) | public |

The service conditions:

| Was | Now |
|---|---|
| `$args['proxycheck_api_key']`, `ipqs_api_key`, `ipinfo_api_key`, `abuseipdb_api_key` | the key is the client's, handed to `register()` |
| `required_args => [ 'ip', '…_api_key' ]` | none: the address comes from the request when there is no `ip` argument |
| a failed lookup answered `false`, `0` or `''` | null -- no answer -- so the rule does not match |
| `Clients\*::reset_cache()`, `clear_cache()` | `Conditions::reset()` |

Answers that changed:

* Every client refuses an address that is not public before asking. Only IPinfo did.
* Error codes start with the provider's id. IPinfo, IPQualityScore and ProxyCheck said `api_error`, `json_error`, `http_error`, `invalid_ip` with no prefix.
* minFraud remembers a failure for a minute, as the others did.
* IPQualityScore's `success: false` (a bad key, no credits) is an error. It was cached as an answer with every field empty.
* ProxyCheck's `status: denied` is an error, like `error`. ProxyCheck's dashboard exports are cached as arrays; they were cached as objects under settings the trait never had, so they never were.
* ProxyCheck's verdict without a country: a proxy is still blocked. It became `na` whenever ProxyCheck sent no country, and it now does only for a clean address when countries are blocked.
* IPinfo's `get_field()` reads the plain-text answer IPinfo sends. It tried to decode it as JSON and failed. A field name is checked before it goes into the URL.
* IPinfo's `get_latitude()` and `get_longitude()` read `loc` too, as `get_coordinates()` did.
* IPQualityScore's `scan_file_for_malware()` sends a multipart body. A `CURLFile` in the body never reached the API through the WordPress HTTP API.
* IPQualityScore's `validate_transaction()` takes the `Transaction` builder as well as an array.
* Text domain `arraypress` is `sugarcommerce`.

## Requirements

* PHP 8.3 or later
* WordPress 7.1 or later
* sugarcommerce/network and sugarcommerce/geo
* sugarcommerce/conditions, for the rules
* A key for the service you use, except IPinfo and ProxyCheck on their free allowances

## License

GPL-2.0-or-later
