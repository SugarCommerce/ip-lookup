# IP Lookup

Ask a fraud or location service about an IP address from WordPress, and get
the same answer back whichever service it was.

## What it does

AbuseIPDB, IPinfo, IPQualityScore and ProxyCheck each answer "who is behind
this address?" in their own shape, with their own idea of a score and their
own way of saying it went wrong. This gives each one a client on the
WordPress HTTP API -- the address and email questions a checkout asks -- and one
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

* Ask four services about an address and read one answer: `lookup( $ip )`
* Know when a service did not say, rather than reading silence as "no"
* Fall back to a second service only when the first fails
* Check an email too: IPQualityScore's validation, ProxyCheck's disposable-address check
* Cache answers and remember failures, per key, with the lifetimes you choose
* Give owners rules like "Proxy is yes" or "VPN Operator is any of Mullvad", under ids that stay put

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

Each is a client for the address and email questions, and a `Provider` for the common answer.
Its answer classes sit beside it in `Providers/<Name>/`; where a class has
more than one job, each job is a trait in `Traits/<Class>/`.

| Class | Key | Common answer |
|---|---|---|
| `Providers\AbuseIPDB` | the API key | abuse confidence as risk, abusive at 75, Tor, hosting from the usage type |
| `Providers\IPInfo` | a token, or none for the free allowance | location and network; proxy, VPN, Tor, relay and hosting on the Business plan |
| `Providers\IPQualityScore` | the API key | fraud score, proxy, VPN, Tor, bot, recent abuse, location, network |
| `Providers\ProxyCheck` | the API key, or none for the free allowance | risk, proxy, VPN, Tor, hosting, location, network |

Every client takes its settings as an array, and has setters for them:

```php
new IPQualityScore( $key, array(
	'cache'       => true,   // set_cache_enabled()
	'cache_ttl'   => 3600,   // set_cache_ttl(); ProxyCheck defaults to 600
	'failure_ttl' => 60,     // set_failure_ttl(); 0 retries every time
	'strictness'  => 1,      // IPQualityScore only: 0 to 3
) );

new AbuseIPDB( $key, array( 'max_age_days' => 30 ) );
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
abuse confidence, IPQualityScore's fraud score, ProxyCheck's risk.
Compare a score with the same service's
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
`lookup( $ip ): Result|WP_Error`. Extending sugarcommerce/network's
`SugarCommerce\Network\Remote\Service` -- the family's one cached-API base,
which every provider here is built on -- gives it the key, the cache, the
failure memory and `is_lookupable()`. Set `CACHE_GROUP = 'iplookup'` to keep
its transients with the others'.

## Emails, batches and the rest

```php
$ipqs->validate_email( $email );               // ->is_disposable(), ->is_leaked(), ->get_deliverability()

$proxycheck->check_email( $email, true );      // true sends only the domain
$proxycheck->check_ips( $ips );                // a batch: 100 without a key, 1,000 with
$proxycheck->set_blocked_countries( array( 'RU' ) )->set_allowed_countries( array( 'GB' ) );

$ipinfo->get_batch_info( $ips );               // cached ones are not asked again
$ipinfo->get_field( $ip, 'country' );          // plain text
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

The ids are fixed -- `proxycheck_is_vpn`, `ipqs_fraud_score`,
`ipinfo_is_hosting`, `abuseipdb_confidence_score` and the rest -- so rules
saved against them keep working. A provider of your own gets `{id}_risk_score`, `{id}_is_proxy`, `{id}_is_vpn`,
`{id}_is_tor`, `{id}_is_hosting` and `{id}_country`.
`Conditions::definitions( $client )` returns them without registering.

The address is the `ip` argument, or `ip_address`, or what the conditions
library resolves -- its `ip` provider, else `REMOTE_ADDR`. Email conditions
need `email`. A lookup that fails is no answer: the condition gives null and
the rule does not match, so "VPN is no" cannot pass because the service was
down. Each answer is asked for once per request, however many conditions
read it.

## Layout

* `src/Lookup.php`, `Provider.php` and `src/Providers/`: asking one service or
  several. `src/Conditions.php` (with `src/Traits/Conditions/`) builds the
  rules a shop owner picks from.
* `src/Models/`: data shapes and nothing that does work. `Result.php` is the
  common answer; `IPInfo/`, `AbuseIPDB/`, `IPQualityScore/` and `ProxyCheck/`
  hold each service's own answer, read field by field.
* `src/Traits/ProxyCheck/` and `src/Traits/ProxyCheckIP/`: the jobs the larger
  ProxyCheck classes are split into. `src/Support/`: the address and field
  readers every provider shares.

## Security

* An address is asked about only when it is public, and always in its one standard spelling: a VPN written out long-hand still meets ProxyCheck's verdict, and costs one request, not one per spelling
* Every field of an answer is read as its type: a malformed or hostile answer is no answer, never a fatal error on the checkout
* A link a provider sends -- ProxyCheck's VPN operator URL -- comes through only as an http or https address, never `javascript:`
* A provider's own error text becomes a plain-text, one-line, clipped message, so no markup reaches a notice that prints it
* An IPinfo batch answer is cached only for the addresses that were asked about
* Keys stay out of URLs: AbuseIPDB, IPinfo and IPQualityScore get them in a header; only ProxyCheck, which takes no other way, gets a `key` query parameter, over HTTPS
* A key is never part of an error message or error data, and is a `#[\SensitiveParameter]` everywhere it is passed, so stack traces leave it out
* Every endpoint is a fixed HTTPS address, and every request has a timeout -- an IPinfo batch's held to 1-30 seconds
* Answers are cached per provider, per key and per question, so two accounts or two questions never share one

## Requirements

* PHP 8.3 or later
* WordPress 7.1 or later
* sugarcommerce/network (and through it sugarcommerce/plugin) and sugarcommerce/geo
* sugarcommerce/conditions, for the rules
* A key for the service you use, except IPinfo and ProxyCheck on their free allowances

## License

GPL-2.0-or-later
