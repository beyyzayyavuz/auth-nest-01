## A.1 slowhttptest (Shekyan)
- URL: https://github.com/shekyan/slowhttptest
- Verified: 2026-05-03

### Raw evidence (README Usage)

Default parameters:
```text
test type	SLOW HEADERS
number of connections	50
URL	http://localhost/
verb	GET
interval between follow up data	10 seconds
connections per second	50
test duration	240 seconds
probe connection timeout	5 seconds
max length of followup data field	32 bytes
```

```text
Attack mode options:
-H, B, R or X	specify to slow down in headers section or in message body, -R enables range test, -X enables slow read test
```

Examples:
```bash
Example of usage in slow message body mode:
./slowhttptest -c 1000 -B -g -o my_body_stats -i 110 -r 200 -s 8192 -t FAKEVERB -u https://myseceureserver/resources/loginform.html -x 10 -p 3

Example of usage in slowloris mode:
./slowhttptest -c 1000 -H -g -o my_header_stats -i 10 -r 200 -t GET -u https://myseceureserver/resources/index.html -x 24 -p 3

Example of usage in slow read mode with probing through proxy at x.x.x.x:8080 to have website availability from IP different than yours:
./slowhttptest -c 1000 -X -r 1000 -w 10 -y 20 -n 5 -z 32 -u http://someserver/somebigresource -p 5 -l 350 -e x.x.x.x:8080
```

### Parsed summary

Defaults:
- -c = 50
- -i = 10s
- -r = 50 conn/sec
- max length of followup data field = 32 bytes 

Attack mapping:
- -H → slowloris mode
- -B → slow message body mode
- -X → slow-read mode

Status: ✓ Verified


## A.2 Cloudflare Rate Limiting
- URL: https://developers.cloudflare.com/waf/rate-limiting-rules/
- Best practices: https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/ 
- Verified: 2026-05-03

```text
Enforcing granular access control
Limit by user agent
A common use case is to limit the rate of requests performed by individual user agents. The following example rule allows a mobile app to perform a maximum of 100 requests in 10 minutes. You could also create a separate rule limiting the rate for desktop browsers.
Setting	Value
Matching criteria	User Agent equals MobileApp
Expression	http.user_agent eq "MobileApp"
Counting characteristics	IP
Rate (Requests / Period)	100 requests / 10 minutes
Action	Managed Challenge

Allow specific IP addresses or ASNs
Another use case when controlling access to resources is to exclude or include IP addresses or Autonomous System Numbers (ASNs) from a rate limiting rule.
The following example rule allows up to 10 requests per minute from the same IP address doing a GET request for /status, as long as the visitor's IP address is not included in the partner_ips IP list.
Setting	Value
Matching criteria	URI Path equals /status and Request Method equals GET and IP Source Address is not in list partner_ips
Expression	http.request.uri.path eq "/status" and http.request.method eq "GET" and not ip.src in $partner_ips
Counting characteristics	IP
Rate (Requests / Period)	10 requests / 1 minute
Action	Managed Challenge

Protecting against credential stuffing
A typical use case of rate limiting is to protect a login endpoint against attacks such as credential stuffing ↗. The following example contains three different rate limiting rules with increasing penalties to manage clients making too many requests.

Rule #1
Setting	Value
Matching criteria	Hostname equals example.com and URI Path equals /login and Request Method equals POST
Expression	http.host eq "example.com" and http.request.uri.path eq "/login" and http.request.method eq "POST"
Counting characteristics	IP
Increment counter when	URI Path equals /login and Method equals POST and Response code is in (401, 403)
Counting expression	http.request.uri.path eq "/login" and http.request.method eq "POST" and http.response.code in {401 403}
Rate (Requests / Period)	4 requests / 1 minute
Action	Managed Challenge

Rule #2
Setting	Value
Matching criteria	Hostname equals example.com and URI Path equals /login and Request Method equals POST
Expression	http.host eq "example.com" and http.request.uri.path eq "/login" and http.request.method eq "POST"
Counting characteristics	IP
Increment counter when	URI Path equals /login and Request Method equals POST and Response Status Code is in (401, 403)
Counting expression	http.request.uri.path eq "/login" and http.request.method eq "POST" and http.response.code in {401 403}
Rate (Requests / Period)	10 requests / 10 minutes
Action	Managed Challenge

Rule #3
Setting	Value
Matching criteria	Host equals example.com
Expression	http.host eq "example.com"
Counting characteristics	IP
Increment counter when	URI Path equals /login and Request Method equals POST and Response Status Code is in (401, 403)
Counting expression	http.request.uri.path eq "/login" and http.request.method eq "POST" and http.response.code in {401 403}
Rate (Requests / Period)	20 requests / 1 hour
Action	Block for 1 day
```

Observed example thresholds:
- 100 requests / 10 minutes per IP
- 10 requests / 1 minute per IP for GET /status
- 4 failed POST /login requests / 1 minute per IP (login protection)
- 10 failed POST /login requests / 10 minutes per IP
- 20 failed POST /login requests / 1 hour per IP, followed by block escalation


My comment: Cloudflare does not provide a universal default rate-limit threshold on this page. The documented values are user-defined parameters or scenario-specific examples, not default thresholds.

(Reference from Cloudflare overview: Action behavior: By default, Cloudflare will apply the rule action for the configured duration (or mitigation timeout), regardless of the request rate during this period. Some Enterprise customers can configure the rule to throttle requests over the maximum rate, allowing incoming requests when the rate is lower than the configured limit.)

Status: ✓ Verified



## A.3 — AWS WAF Rate-Based Rules
- URL: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html
- Verified: 2026-05-03

```text
Documentation
AWS WAF
Developer Guide

Rate-based rule high-level settings in AWS WAF
A rate-based rule statement uses the following high level settings:

Evaluation window – The amount of time, in seconds, that AWS WAF should include in its request counts, looking back from the current time. For example, for a setting of 120, when AWS WAF checks the rate, it counts the requests for the 2 minutes immediately preceding the current time. Valid settings are 60 (1 minute), 120 (2 minutes), 300 (5 minutes), and 600 (10 minutes), and 300 (5 minutes) is the default.
This setting doesn't determine how often AWS WAF checks the rate, but how far back it looks each time it checks. AWS WAF checks the rate frequently, with timing that's independent of the evaluation window setting.

Rate limit – The maximum number of requests matching your criteria that AWS WAF should just track for the specified evaluation window. The lowest limit setting allowed is 10. When this limit is breached, AWS WAF applies the rule action setting to additional requests matching your criteria.
AWS WAF applies rate limiting near the limit that you set, but does not guarantee an exact limit match. For more information, see Rate-based rule caveats.

Request aggregation – The aggregation criteria to use on the web requests that the rate-based rule counts and rate limits. The rate limit that you set applies to each aggregation instance. For details, see Aggregating rate-based rules and Aggregation instances and counts.

Action – The action to take on requests that the rule rate limits. You can use any rule action except Allow. This is set at the rule level as usual, but has some restrictions and behaviors that are specific to rate-based rules. For general information about rule actions, see Using rule actions in AWS WAF. For information specific to rate limiting, see Applying rate limiting to requests in AWS WAF in this section.

Scope of inspection and rate limiting – You can narrow the scope of the requests that the rate-based statement tracks and rate limits by adding a scope-down statement. If you specify a scope-down statement, the rule only aggregates, counts, and rate limits requests that match the scope-down statement. If you choose the request aggregation option Count all, then the scope-down statement is required. For more information about scope-down statements, see Using scope-down statements.

(Optional) Forwarded IP configuration – This is only used if you specify IP address in header in your request aggregation, either alone or as part of the custom keys settings. AWS WAF retrieves the first IP address in the specified header and uses that as the aggregation value. A common header for this purpose is X-Forwarded-For, but you can specify any header. For more information, see Using forwarded IP addresses.


Documentation
AWS WAF
Developer Guide

Aggregating rate-based rules in AWS WAF

This section explains your options for aggregating requests.

By default, a rate-based rule aggregates and rate limits requests based on the request IP address. You can configure the rule to use various other aggregation keys and key combinations. For example, you can aggregate based on a forwarded IP address, on the HTTP method, or on a query argument. You can also specify aggregation key combinations, such as IP address and HTTP method, or the values of two different cookies.
You can configure your rate-based rule with the following aggregation options.

Source IP address – Aggregate using only the IP address from the web request origin.
The source IP address might not contain the address of the originating client. If a web request goes through one or more proxies or load balancers, this will contain the address of the last proxy.

IP address in header – Aggregate using only a client address in an HTTP header. This is also referred to as a forwarded IP address.
With this configuration, you also specify a fallback behavior to apply to a web request with a malformed IP address in the header. The fallback behavior sets the matching result for the request, to match or no match. For no match, the rate-based rule doesn't count or rate limit the request. For match, the rate-based rule groups the request together with other requests that have a malformed IP address in the specified header.
Use caution with this option, because headers can be handled inconsistently by proxies and they can also be modified to bypass inspection. For additional information and best practices, see Using forwarded IP addresses in AWS WAF.

ASN – Aggregate using an Autonomous System Number (ASN) associated with the source IP address as an aggregate key. This might not be the address of the originating client. If a web request goes through one or more proxies or load balancers, this contains the address of the last proxy.
If AWS WAF can’t derive an ASN from the IP address, it counts the ASN as ASN 0. If you don't want to apply rate limiting to unmapped ASNs, you can create a scope-down rule that excludes requests with ASN 0.

ASN in header – Aggregate using an ASN associated with a client IP address in an HTTP header. This is also referred to as a forwarded IP address. With this configuration, you also specify a fallback behavior to apply to a web request with an invalid or malformed IP address. The fallback behavior sets the matching result for the request, to match or no match. If you set the fallback behavior to match in the forwarded IP configuration, AWS WAF treats the invalid IP address as a matching value. This allows AWS WAF to continue evaluating any remaining parts of your rate-based rule's composite key. For no match, the rate-based rule doesn't count or rate limit the request.
Use caution with this option, as headers can be handled inconsistently by proxies and they can be modified to bypass inspection. For additional information and best practices, see Using forwarded IP addresses in AWS WAF.

Count all – Count and rate limit all requests that match the rule's scope-down statement. This option requires a scope-down statement. This is typically used to rate limit a specific set of requests, such as all requests with a specific label or all requests from a specific geographic area.

Custom keys – Aggregate using one or more custom aggregation keys. To combine either of the IP address options with other aggregation keys, define them here under custom keys.
Custom aggregation keys are a subset of the web request component options described at Request components in AWS WAF.
The key options are the following. Except where noted, you can use an option multiple times, for example, two headers or three label namespaces.

Label namespace – Use a label namespace as an aggregation key. Each distinct fully qualified label name that has the specified label namespace contributes to the aggregation instance. If you use just one label namespace as your custom key, then each label name fully defines an aggregation instance.
The rate-based rule uses only labels that have been added to the request by rules that are evaluated beforehand in the protection pack (web ACL).
For information about label namespaces and names, see Label syntax and naming requirements in AWS WAF.

Header – Use a named header as an aggregation key. Each distinct value in the header contributes to the aggregation instance.
Header takes an optional text transformation. See Using text transformations in AWS WAF.

Cookie – Use a named cookie as an aggregation key. Each distinct value in the cookie contributes to the aggregation instance.
Cookie takes an optional text transformation. See Using text transformations in AWS WAF.

Query argument – Use a single query argument in the request as an aggregate key. Each distinct value for the named query argument contributes to the aggregation instance.
Query argument takes an optional text transformation. See Using text transformations in AWS WAF.

Query string – Use the entire query string in the request as an aggregate key. Each distinct query string contributes to the aggregation instance. You can use this key type once.
Query string takes an optional text transformation. See Using text transformations in AWS WAF.

URI path – Use the URI path in the request as an aggregate key. Each distinct URI path contributes to the aggregation instance. You can use this key type once.
URI path takes an optional text transformation. See Using text transformations in AWS WAF.

JA3 fingerprint – Use the JA3 fingerprint in the request as an aggregate key. Each distinct JA3 fingerprint contributes to the aggregation instance. You can use this key type once.

JA4 fingerprint – Use the JA4 fingerprint in the request as an aggregate key. Each distinct JA4 fingerprint contributes to the aggregation instance. You can use this key type once.

HTTP method – Use the request's HTTP method as an aggregate key. Each distinct HTTP method contributes to the aggregation instance. You can use this key type once.

IP address – Aggregate using the IP address from the web request origin in combination with other keys.
This might not contain the address of the originating client. If a web request goes through one or more proxies or load balancers, this will contain the address of the last proxy.

IP address in header – Aggregate using the client address in an HTTP header in combination with other keys. This is also referred to as a forwarded IP address.
Use caution with this option, as headers can be handled inconsistently by proxies and they can be modified to bypass inspection. For additional information and best practices, see Using forwarded IP addresses in AWS WAF.
```

Observed defaults/limits:
- Evaluation window default: 300 seconds / 5 minutes.
- Default aggregation: request IP address.
- Source IP address is listed as an aggregation option.
- Minimum configurable rate limit: 10 requests per evaluation window.

Rate threshold:
- No default threshold defined
- Minimum configurable threshold: 10 requests per evaluation window

Interpretation note:
The documentation describes the request limit as a user-configured value and does not state a universal default request-rate threshold.

Aggregation keys:
- Source IP address
- IP address in header / forwarded IP
- ASN / ASN in header
- Count all
- Custom keys:
  - header
  - cookie
  - query argument
  - query string
  - URI path
  - JA3 fingerprint
  - JA4 fingerprint
  - HTTP method
  - IP address combined with other keys

Status: ✓ Verified

## A.4 — k6 Documentation
- URL: https://grafana.com/docs/k6/latest/testing-guides/test-types/
- Verified: 2026-05-03

```text
Load test types
Many things can go wrong when a system is under load. The system must run numerous operations simultaneously and respond to different requests from a variable number of users. To prepare for these performance risks, teams use load testing.

But a good load-testing strategy requires more than just executing a single script. Different patterns of traffic create different risk profiles for the application. For comprehensive preparation, teams must test the system against different test types.

Different tests for different goals
Start with smoke tests, then progress to higher loads and longer durations.
The main types are as follows. Each type has its own article outlining its essential concepts.
Smoke tests validate that your script works and that the system performs adequately under minimal load.
Average-load test assess how your system performs under expected normal conditions.
Stress tests assess how a system performs at its limits when load exceeds the expected average.
Soak tests assess the reliability and performance of your system over extended periods.
Spike tests validate the behavior and survival of your system in cases of sudden, short, and massive increases in activity.
Breakpoint tests gradually increase load to identify the capacity limits of the system.

NOTE
In k6 scripts, configure the load configuration using options or scenarios. This separates workload configuration from iteration logic.

Test-type cheat sheet
The following table provides some broad comparisons.

Type	VUs/Throughput	Duration	When?
Smoke	Low	Short (seconds or minutes)	When the relevant system or application code changes. It checks functional logic, baseline metrics, and deviations
Load	Average production	Mid (5-60 minutes)	Often to check system maintains performance with average use
Stress	High (above average)	Mid (5-60 minutes)	When system may receive above-average loads to check how it manages
Soak	Average	Long (hours)	After changes to check system under prolonged continuous use
Spike	Very high	Short (a few minutes)	When the system prepares for seasonal events or receives frequent traffic peaks
Breakpoint	Increases until break	As long as necessary	A few times to find the upper limits of the system

General recommendations
When you write and run different test types in k6, consider the following.
Start with a smoke test
Start with a smoke test. Before beginning larger tests, validate that your scripts work as expected and that your system performs well with a few users.

After you know that the script works and the system responds correctly to minimal load, you can move on to average-load tests. From there, you can progress to more complex load patterns.
The specifics depend on your use case
Systems have different architectures and different user bases. As a result, the correct load testing strategy is highly dependent on the risk profile for your organization. Avoid thinking in absolutes.

For example, k6 can model load by either number of VUs or by number of iterations per second ( open vs. closed). When you design your test, consider which pattern makes sense for the type.

What’s more, no single test type eliminates all risk. To assess different failure modes of your system, incorporate multiple test types. The risk profile of your system determines what test types to emphasize:

Some systems are more at risk of longer use, in which case soaks should be prioritized.
Others are more at risk of intensive use, in which case stress tests should take precedence.
In any case, no single test can uncover all issues.

What’s more, the categories themselves are relative to use cases. A stress test for one application is an average-load test for another. Indeed, no consensus even exists about the names of these test types (each of the following topics provides alternative names).
Aim for simple designs and reproducible results
While the specifics are greatly context-dependent, what’s constant is that you want to make results that you can compare and interpret.

Stick to simple load patterns. For all test types, directions is enough: ramp-up, plateau, ramp-down.

Avoid “rollercoaster” series where load increases and decreases multiple times. These will waste resources and make it hard to isolate issues.
```

Observed test categories:
- Smoke test
- Load test
- Stress test
- Soak test
- Spike test
- Breakpoint test

Interpretation note:
- Flood scenarios in this thesis align with stress testing
- Controlled request-per-second generation uses ramping-arrival-rate executor

Tool:
- k6 (Grafana)

Status: ✓ Verified

## A.5 — nginx Default Configuration
- Source (HTTP core):
  https://nginx.org/en/docs/http/ngx_http_core_module.html

- Source (Core module):
  https://nginx.org/en/docs/ngx_core_module.html

Verified: 2026-05-03

Syntax:	client_header_timeout time;
Default:	client_header_timeout 60s;
Context:	http, server
Defines a timeout for reading client request header. If a client does not transmit the entire header within this time, the request is terminated with the 408 (Request Time-out) error.

Syntax:	client_body_timeout time;
Default:	client_body_timeout 60s;
Context:	http, server, location
Defines a timeout for reading client request body. The timeout is set only for a period between two successive read operations, not for the transmission of the whole request body. If a client does not transmit anything within this time, the request is terminated with the 408 (Request Time-out) error.

Syntax:	keepalive_timeout timeout [header_timeout];
Default:	keepalive_timeout 75s;
Context:	http, server, location
The first parameter sets a timeout during which a keep-alive client connection will stay open on the server side. The zero value disables keep-alive client connections. The optional second parameter sets a value in the “Keep-Alive: timeout=time” response header field. Two parameters may differ.
The “Keep-Alive: timeout=time” header field is recognized by Mozilla and Konqueror. MSIE closes keep-alive connections by itself in about 60 seconds.

Syntax:	worker_connections number;
Default:	worker_connections 512;
Context:	events
Sets the maximum number of simultaneous connections that can be opened by a worker process.
It should be kept in mind that this number includes all connections (e.g. connections with proxied servers, among others), not only connections with clients. Another consideration is that the actual number of simultaneous connections cannot exceed the current limit on the maximum number of open files, which can be changed by worker_rlimit_nofile.

```markdown
## nginx defaults

Timeout defaults:
- client_header_timeout: 60s
- client_body_timeout: 60s
- keepalive_timeout: 75s

Worker model:
- worker_connections: 512 by nginx core module default
  (Interpretation note: deployment-dependent)

Interpretation note: (My comment)
- Slowloris primarily interacts with client_header_timeout
- Slow POST primarily interacts with client_body_timeout
- Connection persistence interacts with keepalive_timeout

Status: ✓ Verified
```

# KATEGORİ C — OWASP / RFC

## C.1 — OWASP Automated Threats to Web Applications
- URL: https://owasp.org/www-project-automated-threats-to-web-applications/
- Handbook URL: https://github.com/OWASP/www-project-automated-threats-to-web-applications/blob/master/assets/files/EN/automated-threat-handbook-EN-1v30.pdf
- Document version: V1.30
- Verified: 2026-05-04

## OAT-008 Credential Stuffing

Page 47, Digital Page Number 53

Description:
Lists of authentication credentials stolen from elsewhere are tested against the
application’s authentication mechanisms to identify whether users have re-used the
same login credentials. The stolen usernames (often email addresses) and password
pairs could have been sourced directly from another application by the attacker,
purchased in a criminal marketplace, or obtained from publicly available breach data
dumps.
Unlike OAT-007 Credential Cracking, Credential Stuffing does not involve any brute-
forcing or guessing of values; instead credentials used in other applications are being
tested for validity.

Possible Symptoms:
Sequential login attempts with different credentials
from the same HTTP client (based on IP, User Agent,
device, fingerprint, patterns in HTTP headers, etc.)
High number of failed login attempts
Increased customer complaints of account hijacking
through help center or social media outlets

Sectors Targeted:
Entertainment, Financial, Government, Retail

Parties Affected:
Many Users, Application Owner

Data Commonly Misused:
Authentication Credentials


Suggested Threat-Specific Countermeasures:
Class Threat-Specific Comments
Value Consider providing guidance and encouragement to users about how to select stronger and unique
passwords, and the importance of protecting relevant password recovery mechanisms (e.g. email
account, mobile phones).
Requirements Testing Document acceptable use of authentication functions; define additional requirements.
Define test cases for OAT-008 Credential Stuffing that confirm the application will detect and/or
prevent users attempting to use account credentials in bulk.
Capacity Not applicable
Obfuscation Consider randomising the content and URLs of authentication form pages, tying these changes to the
individual user’s session, verifying the changes at each authentication step, and restricting any identified
automated usage.
Fingerprinting Consider identifying and restricting automated usage by fingerprinting the User Agent for its unique
characteristics.
Reputation Consider identifying and restricting automated usage by reputation methods. In particular, consider
using public breach data to identify at-risk user accounts and force a password change, or increase
anti-fraud measures on these accounts. Consider using geolocation and/or IP address block lists to
prevent access to authentication functions. Consider using email address reputation services, if used for
username.
Authentication Consider not permitting social media login. Consider methods to attempt to ensure users have unique
passwords such as expiring passwords periodically and preventing password re-use. Consider
enhancing authentication by adding CAPTCHA, or adding application-specific challenge questions, or
using strong authentication such as two factor authentication. Consider preventing users from utilising
email addresses as usernames, or using application-specific usernames which are less likely to exist
on other systems. Consider stricter measures for user accounts with greater permissions (e.g.
staff, moderators, content administrators, system accounts). Consider pre-registering users and
implementing strong authentication for access to any exposed authentication APIs.
Rate Limit the number of authentication attempts (success or failure) per session/user/IP address/device/
fingerprint.
Monitoring Log successful and unsuccessful authentication attempts across all functions (register, logon, password
reset, password change, username change, re-authentication, etc) and channels (web, mobile app,
call centre, etc); monitor rates relative to normal activity and also relative the usage of the rest of the
application. Identify account hijacking reports from customers; monitor absolute numbers and trends.
Instrumentation Consider blocking or delaying access by users in a particular session, IP address/range or geolocation or
everyone once Monitoring has identified a real Credential Stuffing attack, or other anomalous behaviour
that has identified the user as an attacker.
Contract Response Sharing Define service limits for any authentication APIs.
Define actions to be taken in the event a Credential Stuffing attack is detected.
Participate in threat intelligence exchanges and contribute Credential Stuffing attack data to sector-wide
sharing systems.

## OAT-014 Vulnerability Scanning

Page 59, Digital Page Number 65

Description
Systematic enumeration and examination of identifiable, guessable and unknown
content locations, paths, file names, parameters, in order to find weaknesses and
points where a security vulnerability might exist. Vulnerability Scanning includes both
malicious scanning and friendly scanning by an authorised vulnerability scanning
engine. It differs from OAT-011 Scraping in that its aim is to identify potential
vulnerabilities.
The exploitation of individual vulnerabilities is not included in the scope of this
ontology, but this process of scanning, along with OAT-018 Footprinting, OAT-004
Fingerprinting and OAT-011 Scraping often form part of application penetration
testing.

Possible Symptoms:
Highly elevated occurrence of errors (e.g. HTTP
status code 404 not found, data validation failures,
authorisation failures)
Extremely high application usage from a single IP
address
Exotic value for HTTP user agent header
High ratio of GET/POST to HEAD requests for a user/
session/IP address compared to typical users
Low ratio of static to dynamic content requests for a
user/session/IP address compared to typical users
Multiple misuse attempts against application entry
points
Parameter/header fuzzing

Sectors Targeted:
Education
Entertainment
Financial
Government
Health
Retail
Technology
Social Networking

Parties Affected:
Application Owner

Data Commonly Misused:
Other Business Data
Public Information

Suggested Threat-Specific Countermeasures:
Class Threat-Specific Comments
Value Develop and deploy applications securely, identify and fix security issues as soon and quickly as
possible.
Requirements Not applicable
Testing Define test cases for OAT-014 Vulnerability Scanning that confirm the application will detect and/or
prevent users scanning it for vulnerabilities.
Capacity Not applicable
Obfuscation Consider making the application behaviour and/or structure so that vulnerability scanners/crawlers/
testers are seemingly unable to ever complete a full site scan and/or unable to access some parts of an
application.
Fingerprinting Consider identifying and restricting automated usage by fingerprinting the User Agent for its unique
characteristics.
Reputation Consider denying or restricting access from IP addresses known to be vulnerability scanners or cloud
providers.
Authentication Consider requiring normal or strong authentication for some or all parts of the application. Consider
requiring periodic and/or aspect-based reauthentication.
Rate Limit the number of input validation and/or authorisation failures per session/user/IP address/device/
fingerprint.
Monitoring Log successful and failed authentications, authorisation failures, input validation failures; monitor rates
relative to normal activity and also relative the usage of the rest of the application.
Instrumentation Implement user and system wide trend detection points together with request, input validation and
authorisation detection points. Consider blocking users or logging them out for non-normal use of the
application.
Contract Define T&Cs to explicitly ban users from scanning the application for vulnerabilities, and consider
requiring opt-in agreement to these before the application can be use. Define approved methods of
engagement for authorised vulnerability scanning.
Response Sharing Define actions to be taken in the event a Vulnerability Scanning attack is detected.
Participate in relevant threat intelligence sharing initiatives.

## OAT-011 Scraping 

Page 53, Digital Page Number 59

Description
Collecting/copying accessible data and/or processed output, for subsequent use such
as exploitation of proprietary data, or price-fixing. Some scraping may use fake or
compromised accounts, or the information may be accessible without authentication.
The scraper may attempt to read all accessible paths and parameter values for pages
and APIs, collecting the responses and extracting data from them. Scraping can be
ongoing, or be more periodic in nature. Scraping can be used to gain insight into
design/operation - perhaps for cryptanalysis, reverse engineering, or session analysis.
When another application is being used as an intermediary between the user(s) and
the real application, see OAT-020 Account Aggregation. If the intent is to obtain cash
or goods, see OAT-012 Cashing Out instead.

Sectors Targeted:
Education
Entertainment
Financial
Government
Health
Retail
Technology
Social Networking

Parties Affected:
Many Users
Application Owner

Data Commonly Misused:
Authentication Credentials
Payment Cardholder Data
Other Financial Data
Medical Data
Other Personal Data
Intellectual Property
Other Business Data
Public Information

Possible Symptoms:
Unusual request activity for selected resources (e.g.
high rate, high number, fixed period)
Duplicated content from multiple sources in search
engine results
Decreased search engine ranking
Increased network bandwidth usage
New competitors with similar service offerings
Unauthorised commercialisation or resale of
proprietary data
Erosion of proprietary asset return on investment (RoI)

Suggested Threat-Specific Countermeasures:
Class Threat-Specific Comments
Value Consider using aggregation, and/or anonymisation and/or pseudonymisation. Consider data
minimisation such as reducing the data fields collected and subsequently output, and/or reducing the
retention period, permanent deletion of data no longer required. Consider outputting truncated,
masked, abbreviated or encrypted data. Consider penalising access to data.
Requirements Testing Document what is acceptable usage and what is unacceptable scraping; define additional requirements.
Define test cases for OAT-011 Scraping that confirm the application will detect and/or prevent users
attempting to scrape content and/or other data.
Capacity Not applicable
Obfuscation Consider randomising the content and URLs of content, tying these changes to the individual user’s
session, verifying the changes at each request, and restricting any identified automated usage.
Fingerprinting Consider identifying and restricting automated usage by fingerprinting the User Agent for its unique
characteristics.
Reputation Consider identifying and restricting automated usage by fingerprinting the User Agent for its unique
characteristics.
Authentication Consider requiring greater identity authentication for access. Consider pre-registering users and
implementing strong authentication for access to any exposed APIs.
Rate Consider adding random delays in responses. Consider capping rate of application use per session/user/
IP address/device/fingerprint.
Monitoring Log request timestamps and rate of data access; monitor for faster-than-average access, repeated
access, and non-normal access patterns.
Instrumentation Consider blocking or delaying access or delaying access by users in a particular session, IP address/
range or geolocation once Monitoring has identified a real Scraping attack, or other anomalous
behaviour that has identified the user as an attacker.
Contract Define T&Cs to explicitly define acceptable use that excludes Scraping. Use T&Cs to permit indexing but
not re-use. Implement licensing conditions which require scrapers to contribute monetarily to the
website owner.
Response Sharing Define actions to be taken in the event a Scraping attack is detected.
Participate in threat intelligence exchanges and contribute attack data to sector-wide sharing systems.
Note that in certain applications, some types of Scraping may be desirable, or even encouraged, rather than being threats.

## OAT-002 Token Cracking

Page 35, Digital Page Number 41

Description
Identification of valid token codes providing some form of user benefit within the
application. The benefit may be a cash alternative, a non-cash credit, a discount, or
an opportunity such as access to a limited offer.
For cracking of usernames, see OAT-007 Credential Cracking instead.

Parties Affected
Entertainment
Financial
Retail

Parties Affected
Application Owner
Third Parties

Data Commonly Misused
Other Business Data

Possible Symptoms
Multiple failed token attempts from the same user and/or IP address and/or User Agent and/or device ID/fingerprint
High number of failed token attempts

Suggested Threat-Specific Countermeasures
Class Threat-Specific Comments
Value Consider decreasing the attractiveness of tokens in the application, by removing them, reducing their
value, or limiting their life or scope of use. Consider disallowing vouchers schemes.
Requirements Document all locations where coupon numbers, voucher codes, discount tokens and similar elements
are used in the application. Specify limits on acceptable use of each function related each token; define
additional requirements.
Testing Define test cases for OAT-002 Token Cracking that confirm the application will detect and/or prevent
users trying to enumerate and/or use tokens at a disproportionate scale.
Capacity Not applicable
Obfuscation Consider randomising the content and URLs of token submission pages, tying these changes to the
individual user’s session, verifying the changes at each token-related request, and restricting any
identified automated usage.
Fingerprinting Consider identifying and restricting automated usage by fingerprinting the User Agent for its unique
characteristics.
Reputation Authentication Consider identifying and restricting automated usage by reputation methods.
Consider requiring identity authentication, re-authentication or some other increased authentication
assurance for access to areas where tokens are generated or consumed.
Rate Monitoring Limit the number of failed token submission attempts per session/user/IP address/device/fingerprint.
Log successful and failed token submissions; monitor rates relative to normal activity and also relative
the usage of the rest of the application. Where applicable, track token creation trends.
Instrumentation Consider blocking or delaying access by users in a particular session, IP address/range or geolocation
once Monitoring has identified a real Token Cracking attack, or other anomalous behaviour that has
identified the user as an attacker.
Contract Define T&Cs to explicitly ban users from misusing the application to undertake Token Cracking, and
similar activities. Define service limits for any token validation or creation APIs.
Response Sharing Define actions to be taken in the event a Token Cracking attack is detected.
Participate in relevant threat intelligence exchanges and contribute attack data to sector-wide sharing
systems.

## OAT-015 Denial of Service

Page 61, Digital Page Number 67

Description
Usage may resemble legitimate application usage, but may lead to reduced
performance (e.g. slow down, brownout) and eventual exhaustion of resources such
as file system, memory, processes, threads, CPU, and human or financial resources.
The resources might be related to web, application or databases servers or other
services supporting the application, such as third party APIs, included third-party
hosted content, or content delivery networks (CDNs). The application may be affected
as a whole, or the attack may be against individual users such as account lockout.
This ontology’s scope excludes other forms of denial of service that affect web
applications, namely HTTP Flood DoS (GET, POST, Header with/without TLS), HTTP
Slow DoS, IP layer 3 DoS, and TCP layer 4 DoS. Those protocol and lower layer aspects
are covered adequately in other taxonomies and lists.

Sectors Targeted
Entertainment
Financial
Government
Retail
Technology
Social Networking

Parties Affected
Few Individual Users
Many Users
Application Owner

Possible Symptoms
Spikes in CPU, memory and network utilization
Unavailability of part or all of the application
Rise in user account lockouts
Rise is complaints about poor performance
Reduced website performance and service
degradation

Suggested Threat-Specific Countermeasures
Class Threat-Specific Comments
Value Requirements Consider reducing and/or eliminating resource intensive functionality, or using alternatives.
Document average and peak (at different durations) usage of all functions and paths, including APIs,
included content and third-party components and services, for all types of permitted automated
robot activity as well as normal user usage during standard, seasonal, and other relevant scenarios.
Define additional requirements.
Testing Define test cases for OAT-015 Denial of Service that confirm the application will detect and/or prevent
users performing application denial of service. These test cases should include attacks against
particularly susceptible functions, against user accounts, or against other application system resources.
Capacity Identify all capacity pinch points, for both normal and peak usage. Provide adequate greater capacity
for system components based on risk. This may include providing specific API or data feeds for data
provision, application configuration, SSL configuration, designing lowly-loaded systems, load balancing,
auto-scaling, caching, content delivery networks, SSL accelerators/terminators, XML gateways, content
switching, query caching, query optimisation, application delivery controller, denial of service (DoS)
protection service, etc.
Obfuscation Not applicable
Fingerprinting Consider identifying and restricting automated usage by fingerprinting the User Agent for its unique
characteristics.
Reputation Authentication Consider identifying and restricting automated usage by reputation methods.
Consider requiring authentication or enhanced authentication for high resource usage aspects of the
application.
Rate Monitoring Consider limiting availability and/or rate of usage of high resource usage aspects of the application.
Log application site usage, account lockout, product/service availability, critical resource usage, etc;
monitor against multiple alerting thresholds as well as changes to trends.
Instrumentation Consider blocking or delaying application access by individual users or groups of users based on
behaviour and/or session, and/or IP address/range and/or geolocation once Monitoring has identified
a real Denial of Service attack, or other anomalous behaviour that has identified the user(s) as an
attacker(s). Consider disabling at resource intensive functions progressively to maintain availability of
other aspects.
Contract Response Sharing Define acceptable use and service limits for the application, including any APIs and related components.
Define actions to be taken in the event a Denial of Service attack is detected.
Participate in threat intelligence exchanges and contribute Denial of Service attack data to sector-wide
sharing systems.
Note that web application denial of service can often be the side effect of some other web application automated threat.
Separately, non web application denial of service such as network, HTTP and SSL/TLS may also occur.

## OAT-019 Account Creation

Page 69, Digital Page Number 75

Description
Bulk account creation, and sometimes profile population, by using the application’s
account sign-up processes. The accounts are subsequently misused for generating
content spam, laundering cash and goods, spreading malware, affecting reputation,
causing mischief, and skewing search engine optimisation (SEO), reviews and surveys.
Account Creation generates new accounts - see OAT-007 Credential Cracking and
OAT-008 Credential Stuffing for threat events that use existing accounts.

Possible Symptoms:
Higher than average account creation rate compared
to average rate over time
Accounts with incomplete information relative to the
typical account holders e.g. incomplete profile fields
Accounts created but which are not used immediately
Accounts created with disproportionate use, and/or
misuse, of the application’s functionalities
Stolen/re-used/AI-generated profile photo, use of
generic bio or generated account name
Unusual temporal functional use behaviour

Sectors Targeted:
Education
Entertainment
Financial
Retail
Social Networking

Parties Affected:
Application Owner

Data Commonly Misused:
Authentication Credentials
Other Business Data

Suggested Threat-Specific Countermeasures:
Class Threat-Specific Comments
Value Requirements Testing Consider limiting the functionality and/or capacity available to newly, and/or recently created, accounts.
Document acceptable use of all possible account creation functions; define additional requirements.
Define test cases for OAT-019 Account Creation that confirm the application will detect and/or prevent
users attempting to create accounts in bulk.
Capacity Not applicable
Obfuscation Consider randomising the content and URLs of account creation form pages, tying these changes to the
individual user’s session, verifying the changes at each request, and restricting any identified automated
usage.
Fingerprinting Consider identifying and restricting automated usage by fingerprinting the User Agent for its unique
characteristics.
Reputation Consider removing self-registration to existing known people (e.g. approved suppliers and/or
customers). Consider identifying and restricting automated usage by reputation methods. In particular,
consider using geolocation and/or IP address block lists to prevent access to registration/sign-up or
to apply enhanced authentication requirements. Consider using reputation services (e.g. IP address,
email address, postal address) to assist in
Authentication Consider removing self-registration. Consider not permitting social media login. Consider out-of-band
verification (e.g. email address verification). Consider enhancing authentication by adding CAPTCHA, or
adding application-specific challenge questions, or using strong authentication such as two factor
authentication. Consider pre-registering users and implementing strong authentication for access to any
exposed authentication APIs.
Rate Monitoring Limit the rate of creation of accounts.
Log application usage by function for each user; monitor rate of application use relative to typical usage.
Log account creation dates/times; monitor period from time of account creation to first use, and also
monitor completeness of optional account information, and whether any profile text or images are
generic, re-used or copied from elsewhere.
Instrumentation Consider blocking or delaying access or delaying access by users in a particular session, IP address/
range or geolocation or everyone once Monitoring has identified a real Account Creation attack, or other
anomalous behaviour (possibly much later) that has identified the user as an attacker.
Contract Response Sharing Define T&Cs to explicitly define acceptable use. Define service limits for any account creation APIs.
Define actions to be taken in the event an Account Creation attack is detected.
Participate in threat intelligence exchanges and contribute Account Creation attack data to sector-wide
sharing systems.

## OAT-021 Denial of Inventory

Page 73, Digital Page Number 79

Description
Selection and holding of items from a limited inventory or stock, but which are never
actually bought, or paid for, or confirmed, such that other users are unable to buy/
pay/confirm the items themselves. It differs from OAT-005 Scalping in that the goods
or services are never actually acquired by the attacker.
Denial of Inventory is most commonly thought of as taking ecommerce items out
of circulation by adding many of them to a cart/basket; the attacker never actually
proceeds to checkout to buy them but contributes to a possible stock-out condition.
A variation of this automated threat event is making reservations (e.g. hotel rooms,
restaurant tables, holiday bookings, flight seats), and/or click-and-collect without
payment. But this exhaustion of inventory availability also occurs in other types of
web application such as in the assignment of non-goods like service allocations,
product rations, availability slots, queue positions, and budget apportionments.
If server resources are reduced see OAT-015 Denial of Service instead. Like OAT-005
Scalping , Denial of Inventory also reduces the availability of goods or services.

Possible Symptoms:
Inventory balances reduce quickly
Increased stock held in baskets or reservations
Elevated basket abandonment
Reduced use of payment step
Increasing complaints from users being unable to obtain goods/services

Sectors Targeted
Education
Entertainment
Financial
Government
Health
Retail
Technology

Parties Affected:
Few Individual Users
Application Owner
Society

Suggested Threat-Specific Countermeasures:
Class Threat-Specific Comments
Value Consider requiring a deposit to reserve or book the goods/services. Consider providing incentives for
quicker progression through checkout to payment.
Requirements Document allocation/assignment policies and related settings/rules for identified applicable capacities
and time outs. Consider how settings/limits should vary for seasonal or time-limited or low-availability
stock.
Testing Define test cases for OAT-021 Denial of Inventory that confirm the application will detect and/or
prevent users attempting to remove inventory/stock from availability and hold onto it without
paying/completing.
Capacity Not applicable
Obfuscation Consider randomising the content and URLs of product/catalogue pages and addition to basket/
assignment processes.
Fingerprinting Consider identifying and restricting automated usage by fingerprinting the User Agent for its unique
characteristics.
Reputation Authentication Consider identifying and restricting automated usage by reputational methods.
Consider requiring greater identity authentication before goods/services can be allocated/assigned.
Empty all items from baskets of anonymous users when their session expires.
Rate Inform users of item holding time-outs. Consider limiting individual basket capacities. Consider
increasing basket and basket item time-outs, or making these dynamic in response to demand and/or
expiration dates. Consider reducing the time period reservation allocations remain valid. Consider
disabling cash purchases for goods/services at certain times. Consider moving older baskets to wish
lists. Consider limiting addition/re-addition to basket/allocation/assignment mechanisms per user, per
group of users, per IP address/range, per device ID/fingerprint etc.
Monitoring Log inventory allocation and de-allocation for each good/service item, log per session allocation,
individually and in aggregate, across all channels (web, mobile app, call centre, physical retail stores,
etc). Log drop-out rates for reservation/click & collect/pay by cash services. Identify stock issues raised
by customers/clients/citizens; monitor trends.
Instrumentation Consider emptying or disabling baskets etc in a particular session, IP address range or geolocation once
Monitoring has identified a real Denial of Inventory attack, or other anomalous behaviour that has
identified the user as an attacker
Contract Define T&Cs to explicitly ban users from using the application in a way that leads to denial of inventory.
Use contracts to prohibit employees and partners from undertaking or instigating such attacks against
competitors.
Response Sharing Define actions to be taken in the event a Denial of Inventory attack is detected.
Participate in threat intelligence exchanges.

## OAT-005 Scalping

Page 41, Digital Page Number 47

Description
Acquisition of goods or services using the application in a manner that a normal user
would be unable to undertake manually.
Although Scalping may include monitoring awaiting availability of the goods or
services, and then rapid action to beat normal users to obtain these, Scalping is
not a “last minute” action like OAT-013 Sniping, nor just related to automation on
behalf of the user such as in OAT-006 Expediting. This is because Scalping includes
the additional concept of limited availability of sought-after or exclusive goods or
services, and is most well known in the ticketing business where the tickets acquired
are then resold later at a profit by the scalpers/touts. This can also lead to a type of
user denial of service, since the goods or services become unavailable rapidly.

Sectors Targeted
Entertainment
Financial
Retail

Parties Affected
Many Users
Application Owner

Possible Symptoms
High peaks of traffic for certain limited-availability goods or services
Increased circulation of limited goods reselling on secondary market

Suggested Threat-Specific Countermeasures
Class Threat-Specific Comments
Value Consider increasing the real or apparent availability of the goods/services. Consider limiting the value
of the good/service by tying its subsequent use specifically to one user, thus reducing its resale value.
Consider penalising rapid and/or repeated purchase.
Requirements Document acceptable use of relevant functions (e.g. selection, ordering, booking, reserving, checkout);
define additional requirements.
Testing Define test cases for OAT-005 Scalping that confirm the application will detect and/or prevent users
attempting to obtain limited-availability/preferred goods by unfair methods.
Capacity Not applicable
Obfuscation Consider randomising the content and URLs of relevant functions, tying these changes to the individual
user’s session, verifying the changes at each request, and restricting any identified automated usage.
Fingerprinting Consider identifying and restricting automated usage by fingerprinting the User Agent for its unique
characteristics.
Reputation Consider identifying and restricting automated usage by reputation methods. In particular, consider
using geolocation and/or IP address block lists and/or reputation services to prevent access to the
good/service allocation functions.
Authentication Consider requiring identity authentication, re-authentication or some other increased authentication
assurance for access to relevant functions, for all users or when there is a suspicion that Scalping is
occurring.
Rate Monitoring Consider adding random delays in responses. Consider implementing queuing systems.
Log good/service allocation; monitor rate of depletion. Monitor availability of goods on secondary
markets.
Instrumentation Consider blocking or delaying access or delaying access by users in a particular session, IP address/
range or geolocation once Monitoring has identified a real Scalping attack, or other anomalous
behaviour that has identified the user as an attacker.
Contract Define T&Cs to explicitly define acceptable use of the application and permissible re-sale/re-use of the
good/service by another party. Use employment contracts to ban staff from leaking information about
availability and other properties of upcoming goods/service releases.
Response Sharing Define actions to be taken in the event a Scalping attack is detected.
Participate in threat intelligence exchanges and contribute Scalping attack data to sector-wide sharing
systems.

### Interpretation / correction note:

The initial thesis reference plan contained some mappings that required correction after source verification.

- For scraping behavior, OAT-011 Scraping is the appropriate OWASP category. OAT-019 refers to Account Creation, not scraping or account aggregation.
- For application-level resource exhaustion or reduced performance, OAT-015 Denial of Service is more appropriate than OAT-021. OAT-021 Denial of Inventory is specific to holding limited inventory, baskets, reservations, or allocation slots without completing purchase or confirmation.
- OAT-015 should be used carefully: the handbook states that HTTP Flood DoS and HTTP Slow DoS are outside the scope of this ontology. Therefore, OAT-015 supports the application-resource exhaustion aspect, while protocol-specific HTTP flood/slow behavior should be supported with separate sources such as k6, nginx, and slowhttptest documentation.
- OAT-005 Scalping is relevant only if the scenario involves unfair automated acquisition of limited-availability goods or services. It should not be used as the main anchor for generic mimicry or flood behavior.
- OAT-002 Token Cracking is relevant for token/code enumeration, such as voucher, coupon, discount, or benefit tokens. It should not be used as a direct replacement for credential stuffing or credential cracking.

Corrected thesis mapping:
- Credential stuffing scenario → OAT-008 Credential Stuffing
- Bot probing / endpoint fuzzing scenario → OAT-014 Vulnerability Scanning
- Scraping scenario → OAT-011 Scraping
- Application-level resource exhaustion / reduced performance → OAT-015 Denial of Service
- Token/code enumeration → OAT-002 Token Cracking
- Bulk account registration → OAT-019 Account Creation
- Inventory/booking/limited-stock holding abuse → OAT-021 Denial of Inventory
- Limited-availability automated acquisition → OAT-005 Scalping

## C.2 — RFC 9110: HTTP Semantics / HTTP Authentication

- URL: https://datatracker.ietf.org/doc/html/rfc9110
- Verified: 2026-05-03
- Document status: Internet Standard
- Published: June 2022
- Note: RFC 9110 obsoletes RFC 7235, so it is the more current reference for HTTP semantics and authentication framework context.

### Key points

- RFC 9110 defines HTTP semantics and shared protocol elements across HTTP versions.
  - Source: Abstract / document metadata.

- HTTP provides a general framework for access control and authentication using challenge-response authentication schemes.
  - Source: Section 11.1 — Authentication Scheme.

- A `401 Unauthorized` response can challenge the user agent using the `WWW-Authenticate` header field.
  - Source: Section 11.3 — Challenge and Response.

- A client/user agent can authenticate itself to an origin server by sending an `Authorization` header field.
  - Source: Section 11.3 and Section 11.6.2 — Authorization.

- The `WWW-Authenticate` header indicates the authentication scheme(s) and parameters applicable to the target resource.
  - Source: Section 11.6.1 — WWW-Authenticate.

- The `Authorization` header contains credentials with authentication information for the requested resource’s realm.
  - Source: Section 11.6.2 — Authorization.

### Relevance

- Useful only if the thesis discusses HTTP authentication mechanisms or header-level authentication flow.
- Provides technical background for how HTTP authentication headers work.
- Does not define credential stuffing; credential stuffing should be cited using OWASP OAT-008.

Status: ✓ Optional reference

# KATEGORİ B — INDUSTRY REPORTS

## B.1 Akamai
## B.1.1 — Akamai SOTI: Apps, APIs, and DDoS 2026
- Subtitle: Prepare for the Convergence Crisis: Mitigating API, AI, and DDoS Risks
- Series: State of the Internet
- Volume/Issue: V12 Issue 01
- Year: 2026
- Verified: 2026-05-06

Industry context

Akamai describes the convergence of web application attacks, API threats, and DDoS attacks as a standard operating pattern rather than a separate set of isolated threats.

Source: Page 3, Introduction

Automation / mimicry context

Akamai states that web application attacks, API abuse, bot activity, and DDoS increasingly appear as parts of the same campaigns. The report also notes that bots, scripted clients, headless browsers, and automation frameworks can maintain state, adapt behavior, and blend into normal traffic patterns.

Source: Pages 4–5, “The economics of modern internet attacks”

API attack growth

- Average daily API attacks increased by 113% year over year.
- Average API attacks per enterprise increased from 121 in 2024 to 258 in 2025.

Source: Page 6, Key insights; Page 7, API security / Table 1

Behavior-based API attacks

- In 2025, 61.18% of API attacks involved unauthorized workflows and abnormal activity.
- In 2024, this value was 30.01%.
- Akamai interprets this as a shift from traditional web attacks toward behavior-based tactics and business logic abuse.

Source: Page 6, Key insights; Page 11, Table 4

Broken authentication / credential abuse context

- Broken Authentication accounted for 18.56% of observed API vulnerability issues.
- Akamai states that weak authentication controls can leave APIs vulnerable to brute-force and credential stuffing attacks.

Source: Page 8, Common API exposures / Table 2

API incident distribution

- Broken Authentication represented 21.33% of API incidents per affected customer.
- Akamai notes that authentication issues continue to challenge organizations and require real-time behavioral/anomaly analysis.

Source: Page 9, Top API incidents / Table 3

Sensitive data exposure

- In 2025, Akamai observed an average of 3,000 APIs per customer containing sensitive data.
- Approximately 12% of those APIs showed security weaknesses.
- 24% of those weaknesses related to sensitive data exposure findings.
- The report emphasizes that API visibility gaps can allow attackers to access valuable data through misconfiguration or overlooked endpoints.

Source: Page 10, “The risks of data leaks”

Layer 7 DDoS growth

- Layer 7 DDoS attacks surged by 104% over 2023–2025.
- The year-over-year increase from 2024 to 2025 was 61%.

Source: Page 6, Key insights; Page 15, Global DDoS attack trends / Figure 1

Layer 7 DDoS mechanism

- Application-layer DDoS campaigns focus on HTTP GET/POST floods and other web protocol abuse.
- These attacks can exhaust CPU and memory on targeted servers, APIs, GenAI services, or websites.
- Botnets may consist of compromised IoT devices, cloud instances, and proxy networks.

Source: Page 14, DDoS attacks / Understanding the layers of DDoS risk

DDoS target expansion

- Akamai states that DDoS campaigns have evolved beyond simple volumetric floods and increasingly target firewalls, APIs, and application servers.
- These attacks can leverage vulnerabilities or misconfigurations.

Source: Page 14, Today’s DDoS landscape

## B.1.2 — Akamai SOTI: Digital Fortresses Under Siege

- Report title: Digital Fortresses Under Siege: Threats to Modern Application Architectures
- Series: State of the Internet/Security
- Volume/Issue: V10 Issue 04
- Year: 2024
- Verified: 2026-05-06

Web application and API attack growth

- Web attacks against applications and APIs increased by 49% between Q1 2023 and Q1 2024.
- Akamai monitored nearly 14 billion attacks per month at the start of 2023, increasing to more than 26 billion monthly attacks in June 2024.

Source: Pages 3–4, Key insights / Web of vulnerabilities

API attack volume

- 108 billion API attacks were recorded from January 2023 through June 2024.
- Akamai states that API abuse can occur in forms such as data breaches, unauthorized access, and DDoS attacks.

Source: Page 3, Key insights

Industry distribution

- Commerce was the most targeted vertical for web application and API attacks, with 164 billion recorded attacks.
- High technology followed with 59 billion attacks.
- Financial services recorded 55 billion attacks.
- Akamai notes that attacks in financial services can lead to compromised account information and opportunities for credential stuffing and related abuse.

Source: Page 7, Industry trends / Figure 3

API attack trend

- In the first half of 2024, Akamai observed 40 billion API attacks.
- This increased from 35 billion API attacks in the same period of the previous year.
- The report states that compromised APIs can provide unauthorized access to sensitive information and may lead to data theft and fraud.

Source: Page 8, Attack trends in APIs

Business logic abuse / behavioral monitoring

- Akamai states that API abuse can come from users or activities that leverage approved connections or credentials.
- The report recommends continuously monitoring APIs, learning API behaviors, threat modeling misuse cases, maintaining API visibility, and using behavioral analytics to detect business logic abuse.

Source: Pages 9–10, Combatting business logic abuse

User activity monitoring

- Akamai emphasizes user activity monitoring as important for identifying potential API abuse.
- The report also recommends API inventory management, rogue/shadow API detection, security posture testing, and operational detection/response.

Source: Page 10, Ensuring a robust comprehensive API security posture

Application-layer DDoS characteristics

- Application-layer DDoS attacks can require less bandwidth, fewer packets, and fewer devices than volumetric attacks.
- Akamai notes that these attacks are often lower in magnitude, sometimes less than 1 Gbps.
- The report describes them as stealthier and severe because attacker requests can appear legitimate and target costly parts of the application.

Source: Page 12, Defending applications and the infrastructure that powers them

Layer 7 DDoS industry distribution

- Akamai observed Layer 7 DDoS attacks to be most prevalent in high technology, commerce, and social media.
- High technology had more than 5 trillion Layer 7 DDoS attacks from Q1 2023 through June 2024.

Source: Page 14, Layer 7 DDoS attacks by vertical / Figure 5

HTTP flood mention

- Akamai notes that HTTP flood attacks were observed in blockchain DDoS attacks.
- This supports HTTP flood as a Layer 7 DDoS pattern, but the main Layer 7 DDoS mechanism should be supported with the broader application-layer DDoS section.

Source: Page 15, Layer 7 DDoS / blockchain discussion

## B.1.3 — Akamai Account Abuse Analysis (Blog Evidence)

- URL: https://www.akamai.com/blog/security/defend-against-account-abuse-in-financial-services
- Source type: Akamai security blog / financial-services case study
- Year: 2024
- Published: July 8, 2024
- Verified: 2026-05-04

Search terms checked:
- "credential stuffing" → attack description identified
- "requests per second" → low-and-slow rate metrics identified
- "bot" → bot-driven attack behavior confirmed

Statistics extracted:

- Annual / global volume:
  Not explicitly provided in this article.
  This is a case study, not a global aggregate report.

- Average observed attack rate:
  ~0.5 requests/sec

- Peak observed attack rate:
  ~1.3 requests/sec

- Attack volume in case study:
  ~12.7 million account abuse requests mitigated in Q2 2024
  ~6.9 million bot requests mitigated in Q2 2024

- Industry:
  Financial services / North American banking case study

- Attack characteristics:
  Bot-driven credential stuffing / account abuse
  Low-and-slow request rates with large case-study volume
  Human-behavior mimicry and telemetry manipulation
  Attempts to evade traditional rate-limiting defenses

Important note:
This source is not a global SOTI credential-stuffing report. It should be used as case-study evidence for low-and-slow account-abuse behavior, not as evidence of annual global credential-stuffing volume or general per-source rate distribution.

Status: ✓ Verified 

## B.1.4 — Akamai SOTI: Defenders’ Guide 2025 

Optional.

## B.2 — Cloudflare DDoS Threat Report Q4

- Radar report URL: https://radar.cloudflare.com/reports/ddos-2025-q4
- Source type: Official Cloudflare Radar quarterly DDoS threat report
- Year/Quarter: 2025 Q4
- Published: 2026-02-05
- Verified: 2026-05-06

Statistics extracted

- Total DDoS attacks in 2025:
  47.1 million DDoS attacks.

- DDoS attack growth:
  DDoS attacks increased by 121% in 2025.
  DDoS attacks increased by 236% between 2023 and 2025.

- Average mitigated attacks:
  5,376 DDoS attacks automatically mitigated every hour in 2025.
  Of these, 3,925 were network-layer attacks and 1,451 were HTTP DDoS attacks.

- Network-layer DDoS attacks:
  34.4 million network-layer DDoS attacks in 2025.
  11.4 million network-layer DDoS attacks in 2024.
  Network-layer DDoS attacks more than tripled year over year.

- Q4 2025 attack composition:
  In 2025 Q4, network-layer DDoS attacks accounted for 78% of all DDoS attacks.
  HTTP DDoS attack count remained approximately the same, but attack size surged.

- Hyper-volumetric HTTP DDoS:
  Aisuru-Kimwolf botnet launched hyper-volumetric HTTP DDoS attacks exceeding 20 million requests/sec.
  During the campaign, the average request-intensive attack size was 54 million requests/sec.
  Maximum request-intensive attack rate recorded during the campaign was 205 million requests/sec.

- Major botnet campaign:
  The “Night Before Christmas” campaign consisted of 902 hyper-volumetric DDoS attacks:
  - 384 packet-intensive attacks
  - 329 bit-intensive attacks
  - 189 request-intensive attacks
  Average: 53 attacks per day.

- Largest non-HTTP volumetric rate:
  One DDoS attack reached 31.4 Tbps and lasted 35 seconds.

- Most targeted industries:
  Telecommunications, Service Providers and Carriers was the most targeted industry.
  Gambling & Casinos and Gaming ranked third and fourth.

- Most attacked locations:
  China, Hong Kong, Germany, Brazil, United States, United Kingdom, Vietnam, Azerbaijan, India, Singapore.

- Top attack source locations:
  Bangladesh, Ecuador, Indonesia, Argentina, Hong Kong, Ukraine, Vietnam, Taiwan, Singapore, Peru.

- Top source networks:
  Cloudflare notes that many attacks came from IP addresses associated with cloud computing platforms and cloud infrastructure providers, including DigitalOcean, Microsoft, Tencent, Oracle, and Hetzner.

### Limitations

- The report does not provide a median or average rate for all HTTP DDoS attacks.
- The 54 Mrps and 205 Mrps values are from a hyper-volumetric botnet campaign, not representative of typical HTTP DDoS traffic.
- The report is useful for production-scale DDoS context, but lab-scale traffic should be described as a scaled analog rather than a direct reproduction.

Status: ✓ Verified

## B.2.1 — Cloudflare DDoS Threat Report Q1

- URL: https://blog.cloudflare.com/ddos-threat-report-for-2025-q1/
- Year/Quarter: 2025 Q1
- Verified: 2026-05-04

Statistics extracted

- Total DDoS attacks:
  20.5 million attacks blocked in Q1 2025.

- Network-layer DDoS attacks:
  16.8 million attacks blocked in Q1 2025.

- HTTP DDoS attack count:
  Not explicitly stated as a standalone number.
  Derived estimate: approximately 3.7 million HTTP DDoS attacks
  based on 20.5M total DDoS attacks minus 16.8M network-layer attacks.

- HTTP DDoS growth:
  HTTP DDoS attacks increased by 118% year over year.

- HTTP DDoS rate distribution:
  94% of HTTP DDoS attacks were ≤ 1 million requests per second.
  Therefore, 6% exceeded 1 million requests per second.
  Median / average L7 request rate was not explicitly provided.

- Attack duration:
  75% of HTTP DDoS attacks ended within 10 minutes.

- Source distribution:
  Provided graphically in the report.
  Top listed source locations include Hong Kong, Indonesia, and Argentina.

- Industry distribution:
  Provided graphically in the report.
  Top targeted industries include gambling, telecom, IT & services, internet, gaming, and banking.

### Limitations

- No exact standalone HTTP DDoS attack count is explicitly provided.
- No median or average HTTP DDoS request rate is provided.
- The ≤1 Mrps figure is a distribution threshold, not the largest observed Layer 7 attack rate.
- Source and industry rankings are graph-based and should be cited as report observations, not universal distributions.

Status: ✓ Verified with interpretation notes

## B.2b — Cloudflare 2026 Threat Report
Use: current threat context, bot-driven login abuse, compromised credentials, industrialized cyber threats
Status: Optional supporting source

## B.3 — Imperva 2025 Bad Bot Report

- Report title: 2025 Bad Bot Report
- Vendor: Imperva / Thales Cybersecurity
- URL: https://www.imperva.com/resources/resource-library/reports/
- Report year: 2025
- Data year: 2024
- Verified: 2026-05-04
- Status: Optional supporting source

### Source purpose

This report is used as optional industry evidence for bot mimicry, bot sophistication, API-targeting behavior, browser impersonation, residential proxy usage, and account takeover automation.

### Key evidence extracted

1. Overall automated / bad bot traffic

- Automated traffic surpassed human traffic in 2024, accounting for 51% of all web traffic.
- Bad bots made up 37% of all internet traffic in 2024.
- Imperva blocked 13 trillion bad bot requests across thousands of domains and industries in 2024.

Source: Pages 2–3 / Executive Summary and Key Findings.

2. Bot sophistication taxonomy

- In 2024, advanced and moderate bot attacks accounted for 55% of all bot attacks.
- Simple bot attacks accounted for 45% of all bot attacks.
- Imperva attributes the rise of simple high-volume bot attacks partly to the increased accessibility of AI-powered automation tools.

Source: Page 4 / Bot Attack Sophistication Trends.

3. API-focused bot attacks

- 44% of advanced bot traffic targeted APIs in 2024.
- Imperva states that bad bots target API business logic to automate payment fraud, account hijacking, and data exfiltration.
- Traditional signature-based controls may fail because API business logic is unique to each organization and bots can mimic legitimate user behavior.

Source: Pages 5 and 9 / Why Modern APIs Must Defend Against Bad Bots and Bot Attacks Exploit API Business Logic.

4. Residential proxy evasion

- 21% of bot attacks routed through ISPs used residential proxies in 2024.
- Residential proxies allow attackers to route malicious traffic through real user devices and residential IP addresses, making detection harder based on IP reputation alone.

Source: Page 5 / Residential Proxies Remain a Preferred Evasion Tactic; Page 15 / Bot Evasion Tactics.

5. Browser impersonation

- Chrome was the most impersonated browser by bad bots in 2024.
- 46% of bad bot attacks declared themselves as Chrome.
- Mobile Safari accounted for 17%, and Mobile Chrome accounted for 14%.
- Imperva explains that attackers impersonate common browsers to blend in with legitimate traffic and bypass basic security controls.

Source: Page 17 / Browser Impersonation by Bad Bots.

6. Bot evasion tactics

Imperva lists several bot evasion techniques, including:
- fake browser identity and browser attributes,
- residential proxies,
- privacy tools,
- API abuse,
- app cracking,
- CAPTCHA bypass,
- property-cycling,
- headless browsers,
- AI-assisted scripting,
- anti-detect browsers,
- polymorphic bots,
- bots-as-a-service platforms.

Source: Pages 15–16 / Bot Evasion Tactics.

7. Account takeover / credential abuse context

- Account Takeover attacks use malicious bots to gain unauthorized access through credential stuffing and credential cracking.
- ATO attacks increased by 40% in 2024 and by 54% since 2022.
- Financial Services was the most targeted industry for ATO attacks, accounting for 22% of ATO attacks.

Source: Pages 18–20 / Account Takeover Attacks.

### Interpretation

This report supports the thesis argument that modern bot traffic can mimic human behavior through browser impersonation, residential proxies, headless browsers, API-first execution, and automation frameworks. It also supports the inclusion of account-takeover and credential-abuse scenarios as bot-driven threats.

This report should be used as supporting industry evidence for bot mimicry and evasion. It should not replace Akamai’s account-abuse blog for specific low-and-slow request-rate calibration.

Status: ✓ Verified as optional bot mimicry / evasion evidence

# KATEGORİ D — ACADEMIC PAPERS

> **En riskli kategori.** Hallucination geçmişi var (Mirai). Her birini
> dikkatli verify et veya **çıkar**.

## D.1 — Antonakakis et al. 2017 Mirai (PARTIALLY VERIFIED)
## Mirai Botnet — Antonakakis et al. 2017 (USENIX Security)

- URL: https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/antonakakis
- Year: 2017
- Page reference: p.2 (Abstract)
- Verified: 2026-05-04

- Findings:
  - Mirai botnet reached a peak size of approximately 600,000 infected devices
  - Analysis covers a 7-month observation period (Aug 2016 – Feb 2017)
  - Botnet composed primarily of IoT and embedded devices

- Use case:
  - Used as an anchor reference for the existence and large-scale nature of IoT-based botnets
  - DOES NOT provide per-bot HTTP request rate or throughput metrics

- Status: ✓ Verified

## D.2 — Wagner & Soto 2002 (VERIFIED)
## Mimicry Attacks — Wagner & Soto 2002 (CCS)

- URL: https://dl.acm.org/doi/10.1145/586110.586145
- Year: 2002
- Page reference: p.1 (Abstract), p.4 (Mimicry concept)
- Verified: 2026-05-04

- Key findings:
  - Mimicry attacks allow attackers to cloak malicious activity by imitating normal behavior
  - IDS systems can be evaded if attackers adapt their behavior to match expected patterns
  - Sophisticated attackers can exploit knowledge of IDS mechanisms to avoid detection

- Use case:
  - Provides the foundational definition of "mimicry attack"
  - Conceptually supports low-and-slow and stealth attack modeling in higher-layer protocols (e.g., HTTP)

- Status: ✓ Verified


## D.5 — Thomas et al. 2017 CCS (UNVERIFIED — verify et)
- **Title:** Data Breaches, Phishing, or Malware? Understanding the Risks of Stolen Credentials  
- **Authors:** Thomas et al.  
- **Year:** 2017  
- **Source:** ACM CCS  
- **URL:** https://dl.acm.org/doi/10.1145/3133956.3134067  
- **Status:** ✓ Verified  2026-05-04

### Keyword Search (PDF)
- `success rate` → password validity and hijacking likelihood analyzed  
- `valid credentials` → match rate between stolen and real accounts identified  
- `account takeover` → hijacking risk quantified  

### Extracted Statistics

- **Valid credential (match) rate:**
  - Data breaches: ~6.9%  
  - Phishing: ~24.8%  
  - Keyloggers: ~11.9%  

- **Abstract summary:**
  - *7%–25% of exposed passwords match a victim’s account*

- **Password reuse rate:**
  - ~17% average reuse across datasets  
  - Range: ~12% – 38% depending on source  

- **Account takeover risk (odds ratio):**
  - Phishing: ~463× more likely than baseline  
  - Keylogger: ~38×  
  - Data breach: ~11×  

**Status:** ✓ Verified

## D.3 — Fogla et al. 2006 (VERIFIED)
## Polymorphic Blending Attacks — Fogla et al. 2006 (USENIX)

- URL: https://www.usenix.org/legacy/event/sec06/tech/full_papers/fogla/fogla.pdf
- Year: 2006
- Page reference: p.1 (Abstract), p.3 (Blending concept)
- Verified: 2026-05-04

- Key findings:
  - Attacks can evade anomaly-based IDS by matching statistical properties of normal traffic
  - Payload byte frequency distribution is a key feature used by IDS (e.g., PAYL)
  - Blending attacks transform malicious payloads to fit normal statistical profiles
  - These attacks are a subclass of mimicry attacks

- Use case:
  - Provides statistical foundation for “traffic blending”
  - Supports behavioral evasion modeling beyond simple polymorphism

- Status: ✓ Verified

## D.4 — Doran & Gokhale 2011 (VERIFIED — LIMITED USE)

**Citation:**
> Doran, D., & Gokhale, S. S. (2011). "Web Robot Detection Techniques: Overview and Limitations." Data Mining and Knowledge Discovery, 22(1-2), 183–210.

**URL:** https://link.springer.com/article/10.1007/s10618-010-0180-z

**Verification Status:** ✓ Verified (Full-text reviewed)

**Key Findings (Verified):**
- Web robot detection relies on behavioral features such as:
  - request rate
  - inter-arrival time
  - session length
  - resource access patterns :contentReference[oaicite:0]{index=0}
- Traffic pattern analysis and statistical modeling are widely used to distinguish bots from human users :contentReference[oaicite:1]{index=1}
- Machine learning approaches leverage these features to improve detection accuracy :contentReference[oaicite:2]{index=2}

**Important Limitation:**
- The paper **does NOT provide explicit numerical thresholds** (e.g., requests per second ranges such as 0.5–5 req/s)
- It is a **survey paper**, focusing on methodologies rather than concrete parameter values

**Use in This Project:**
- Used to justify **feature selection** (request rate, inter-arrival time, session behavior)
- NOT used for **numerical parameter calibration**

**Tez Cümlesi:**
> "Behavioral features such as request rate, inter-arrival time, and session-level patterns are established indicators for distinguishing automated traffic from human users, as identified in prior work [Doran & Gokhale, 2011]. However, numerical rate thresholds are not defined in the study, and thus parameter calibration in this work relies on industry reports."

**Status:** ✓ Included (feature justification only)

## D.6 — Onaolapo et al. 2016 (IMC) — Leaked Credential Usage in the Wild

- **Title:** What Happens After You Are Pwnd: Understanding the Use of Leaked Webmail Credentials in the Wild  
- **Authors:** Onaolapo, Mariconti, Stringhini  
- **Year:** 2016  
- **Source:** IMC (Internet Measurement Conference)  
- **URL:** https://dl.acm.org/doi/10.1145/2987443.2987475  
- **Status:** ✓ Verified  2026-05-04

### Keyword Search (PDF)

- `account access` → attacker behavior after login analyzed  
- `compromise` → account takeover and misuse observed  
- `credentials` → credential leakage and usage methodology described  

⚠️ **Important:**  
- `success rate` → ❌ NOT explicitly provided  
- `reuse rate <5%` → ❌ NOT found in paper  

---

### Experimental Setup (Core Insight)

- 100 Gmail **honeypot accounts** created  
- Credentials deliberately leaked via:
  - Paste sites  
  - Underground forums  
  - Malware  

- Observation period: **7 months**

---

### Key Measured Results

- **326 unique attacker accesses recorded** :contentReference[oaicite:0]{index=0}  
- **90/100 accounts accessed** :contentReference[oaicite:1]{index=1}  
- **36 accounts fully hijacked (password changed)** :contentReference[oaicite:2]{index=2}  

- **Activity breakdown:**
  - 147 emails opened  
  - 845 emails sent  
  - 12 draft emails created :contentReference[oaicite:3]{index=3}  

---

### Attacker Behavior Taxonomy

Paper çok önemli bir şey yapıyor:

#### 1. Curious (en büyük grup)
- Sadece login olup kontrol ediyor
- Çoğu saldırgan bu kategoride

#### 2. Gold Digger
- Finansal veri arıyor (payment, bitcoin vs.)
- Hesabın “değerini” ölçüyor

#### 3. Spammer
- Hesabı spam için kullanıyor

#### 4. Hijacker
- Şifreyi değiştirip hesabı ele geçiriyor

---

### Critical Insight (Tez için ALTIN değerinde)

👉 **36% account takeover (36/100)**

Bu şu demek:
> Leaked credentials → real-world’de ciddi oranda başarılı oluyor

Ama dikkat:
- Bu **login success rate değil**
- Bu **post-access impact (ne kadar zarar veriliyor)**

---

### Stealth & Behavior Insights

- Malware üzerinden gelen saldırganlar:
  - Daha stealth (gizli)
  - Tor kullanıyor
  - User-Agent gizliyor  

- Paste/forum saldırganları:
  - Daha az sofistike  
  - Daha agresif (hijack yapıyor)

---

### Interpretation

This paper does **NOT provide explicit credential stuffing success rates**, but demonstrates that:

- Leaked credentials are actively used in the wild  
- A significant portion of accessed accounts are:
  - Exploited
  - Hijacked
  - Used for financial gain  

- Attackers operate in different sophistication levels and often attempt to:
  - Evade detection  
  - Blend with legitimate users  

---

### Usage in This Project

Bu paper şu şeyleri justify eder:

- ✔ Credential leakage → real exploitation exists  
- ✔ Attackers behave stealthily (low-rate possible)  
- ✔ Account takeover is realistic outcome  
- ✔ Bot mimicry + human-like behavior  

---

### Thesis Citation

> Onaolapo et al. (2016) demonstrate that leaked credentials are actively exploited in the wild, with 90% of honey accounts receiving unauthorized access and 36% being fully hijacked. The study highlights that attackers not only access compromised accounts but also perform targeted actions such as financial data extraction, spam distribution, and account takeover.

