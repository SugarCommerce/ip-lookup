# Tests

`composer test` runs the PHPUnit suite. There is no WordPress to load: the
core functions the library and its dependencies touch are stubbed in
`bootstrap.php`, transients keep to a clock the tests can move, and the
HTTP API answers from a queue (`Support/FakeHttp.php`) that also records
every request, so a test can say exactly what was sent and how often.

- **ResultTest** -- the common answer: cleaning, ASNs, and null as no answer.
- **ServiceTest** -- network's `Remote\Service` through AbuseIPDB: the cache, failures remembered and forgotten, keys kept
  apart, and addresses refused before any request.
- **Providers/** -- each service's endpoints, URLs, refusals and common answer.
- **LookupTest** -- falling back, asking all, once per request.
- **ConditionsTest** -- wp-conditions' ids, null on failure, and a rule
  matched through sugarcommerce/conditions.
