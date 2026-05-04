
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
- -x = 32 bytes

Attack mapping:
- -H → slowloris
- -B → slow-POST (RUDY)
- -X → slow-read

Status: ✓ Verified


## Cloudflare Rate Limiting
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
- 10 requests / 1 minute per IP
- 4 requests / 1 minute (login protection)
- 20 requests / 1 hour (block escalation)

Best practices summary:
Cloudflare recommends endpoint-specific thresholds based on abuse patterns,
resource sensitivity, and expected user behavior.
Important matter: The required values were not set by default yet examples only.

Status: ✓ Verified



## AWS WAF Rate-Based Rules
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

Observed defaults:
- Evaluation window default: 5 minutes (300 seconds)

Rate threshold:
- No default threshold defined
- Minimum configurable threshold: 10 requests per evaluation window

Aggregation keys:
- Default: Source IP
- Header-based IP (Forwarded IP)
- Custom keys (header, cookie, query, URI path, JA3/JA4, method)

Status: ✓ Verified

## A.4 — k6 Documentation
- URL: https://k6.io/docs/test-types/load-test-types/
- Verified: 2026-05-03

```text
Load testing is a subset of performance testing that generally looks for how a system responds to normal and peak usage. You’re looking for slow response times, errors, crashes, and other issues to determine how many users and transactions the system can accommodate before performance suffers.

Testers today typically rely on  open source load testing tools or specialized, cloud-based automation tools, like Grafana Cloud k6, to test the system with virtual users and simulated data volumes to see how the extra load impacts performance. They monitor and measure response time, throughput, and resource utilization to detect potential bottlenecks or scaling issues that need to be addressed before the system is deployed in production.

When you have a fast software development and delivery process, engineering teams need a robust and reliable testing suite that can keep up with the pace of continuous development and deployment. Such a testing platform helps teams ensure the high quality of every release. To make testing reliable, teams should perform different types of load testing across various environments, including development, canary, QA, pre-production, and production. Teams should also automate testing in continuous delivery pipelines to prevent errors when shipping new features or experiments iteratively to the end-user.

Although automation and frequency vary depending on the load testing type, continuous and automated load testing are now standard practices and the end goal for most types of load testing.

Load testing vs. performance testing  

While load testing and performance testing are related, they are distinct types of testing.
As we’ve discussed, load testing simulates user activity to determine how well a system can handle increased traffic or load.
Performance testing is an umbrella term for measuring how well a system or application performs overall. This could include testing for speed, scalability, reliability, and resource utilization in order to identify areas of improvements. Performance testing includes load testing but also encompasses other types of testing, such as browser performance testing and synthetic monitoring.
How many types of load tests are there? 

An application performs differently depending on the volume and duration of traffic it handles at any given moment. You should never assume your app will perform the same when supporting 10 or 100 users vs. 1,000 or 5,000 users and beyond.

There are six common types of load testing that you can execute on your applications to measure performance under different loads.

1. Smoke test

Smoke tests verify the system functions with minimal load, and they are used to gather baseline performance values. Smoke tests are also called shakeout tests.

This test type consists of running tests with a few VUs. For example, more than 5 virtual users (VUs) could be considered a mini-load test. Similarly, the test should be executed for a short period, either a low number of iterations or a duration from seconds to a few minutes maximum.

3. Stress test

Stress tests help you discover how the system functions with the load at peak traffic. Stress testing might also be called rush-hour testing, surge testing, or scale testing. See the What is stress testing in load testing? section to learn more.

4. Spike test

A spike test verifies whether the system survives and performs under sudden and massive rushes of utilization.

Spike tests are useful when the system may experience events with exceptional traffic volumes. Examples of such events include ticket sales (Taylor Swift), product launches (PS5), broadcast ads (Super Bowl), process deadlines (tax declaration), and seasonal sales (Black Friday). Also, spikes in traffic could be caused by more frequent events such as rush hours.

Spike testing increases to extremely high loads in a very short or non-existent ramp-up time. In the same way, the ramp-down is very fast or non-existent, letting the process iterate only once.

This test might include different processes than the previous test types, as spikes often aren’t part of an average day in production. It may also require adding, removing, or modifying processes on the testing script that are not normally incorporated in your average-load tests.
Type	VUs/Throughput	Duration	When?
Smoke	Low	Short (seconds or minutes)	When the relevant system or application code changes. It checks functional logic, baseline metrics, and deviations
Average-load	Average production	Mid (5-60 minutes)	Often to check system maintains performance with average use
Stress	High (above average)	Mid (5-60 minutes)	When system may receive above-average loads to check how it manages
Soak	Average	Long (hours)	After changes to check system under prolonged continuous use
Spike	Very high	Short (a few minutes)	When the system prepares for seasonal events or receives frequent traffic peaks
Breakpoint	Increases until break	As long as necessary	A few times to find the upper limits of the system
```

Observed test categories:
- Load test: validates expected traffic handling
- Stress test: pushes system beyond normal operational capacity
- Spike test: evaluates sudden traffic surges

Methodology mapping:
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
- worker_connections: commonly 512 in default packaged configs
  (deployment-dependent)

Security relevance:
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

Page 47

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

Threat agents (derived)/Possible Symptoms:
Sequential login attempts with different credentials
from the same HTTP client (based on IP, User Agent,
device, fingerprint, patterns in HTTP headers, etc.)
High number of failed login attempts
Increased customer complaints of account hijacking
through help center or social media outlets

Affected industries:
Education, Entertainment, Financial, Government, Health, Retail, Social Networking

Mitigation:
Suggested Threat-Specific Countermeasures
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

Page 59

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

Threat agents (derived)/Possible Symptoms:
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

Affected industries:
Education
Entertainment
Financial
Government
Health
Retail
Technology
Social Networking

Mitigation/ Suggested Threat-Specific Countermeasures:
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

## OAT-019 Account Creation

Page 69 

Description
Bulk account creation, and sometimes profile population, by using the application’s
account sign-up processes. The accounts are subsequently misused for generating
content spam, laundering cash and goods, spreading malware, affecting reputation,
causing mischief, and skewing search engine optimisation (SEO), reviews and surveys.
Account Creation generates new accounts - see OAT-007 Credential Cracking and
OAT-008 Credential Stuffing for threat events that use existing accounts.

Threat agents (derived)/Possible Symptoms:
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

Affected industries:
Education
Entertainment
Financial
Retail
Social Networking

Mitigation/ Suggested Threat-Specific Countermeasures:
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
Page 73 but in digital version its on 79.

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

Threat agents (derived)/Possible Symptoms:
Inventory balances reduce quickly
Increased stock held in baskets or reservations
Elevated basket abandonment
Reduced use of payment step
Increasing complaints from users being unable to obtain goods/services

Affected industries:
Education
Entertainment
Financial
Government
Health
Retail
Technology

Mitigation/ Suggested Threat-Specific Countermeasures:
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


## RFC 7235 — HTTP Authentication
- URL: https://datatracker.ietf.org/doc/html/rfc7235
- Verified: 2026-05-03

Key points:
- Challenge-response model using WWW-Authenticate and Authorization headers
- Defines standard authentication framework for HTTP
- Supports credential-based authentication schemes (e.g., Basic, Digest)

Relevance:
- Credential reuse in HTTP headers enables credential stuffing attacks

Status: ✓ Optional reference

# KATEGORİ B — INDUSTRY REPORTS

## B.1 — Akamai State of the Internet (SOTI) Security Report
## Akamai Account Abuse Analysis (Blog Evidence)
- URL: https://www.akamai.com/blog/security/defend-against-account-abuse-in-financial-services
- Year: 2024
- Verified: 2026-05-04

blog:
- "credential stuffing" → attack description 
- "attempts per second" → per-source rate metrics identified
- "bot" → bot-driven attack behavior confirmed

Statistics extracted:

- Annual / large-scale volume:
  Not explicitly provided in this article
  (case study instead of global aggregate)

- Peak rate (per-source):
  ~1.3 requests/sec

- Typical per-source rate:
  ~0.5 requests/sec (average)

- Attack volume (case study):
  ~12.7 million account abuse requests
  ~6.9 million bot requests (Q2 2024)

- Industry distribution:
  Financial services (banking sector case study)

- Attack characteristics:
  Distributed botnet-based credential stuffing
  Low-and-slow per-source rates with large aggregate volume

Status: ✓ Verified

## B.2 — Cloudflare DDoS Threat Report (Quarterly)
## Cloudflare DDoS Threat Report
- URL: https://blog.cloudflare.com/ddos-threat-report-for-2025-q1/
- Year/Quarter: 2025 Q1
- Verified: 2026-05-04

Statistics extracted:

- Total DDoS attacks:
  20.5 million attacks in Q1 2025

- HTTP DDoS characteristics:
  94% of HTTP attacks were ≤ 1 million requests per second (Largest L7 attack rate)
  Median L7 attack rate: Not explicitly provided (distribution-based reporting)

- Attack growth:
  HTTP DDoS increased by 118% YoY

- Attack duration:
  75% of HTTP attacks end within 10 minutes

- Source distribution:
  Top sources include Hong Kong, Indonesia, Argentina

- Industry distribution:
  Provided in report (graphical)

- Top targeted industries:
    Gambling, Telecom, IT & Services, Internet, Gaming, Banking

Limitations:
- No median/average request rate provided
- No exact HTTP attack count provided

Graphics
https://cf-assets.www.cloudflare.com/zkvhlag99gkb/4sBpHyhcmYaGxx6bYjGhIR/c257628e5f3c3f854f734c371192de00/image2.png
https://cf-assets.www.cloudflare.com/zkvhlag99gkb/4AX4nalnfQuGKu7rea9HLM/7b2c0f6919aab8627ddcf0fff2a2449a/image13.png
https://cf-assets.www.cloudflare.com/zkvhlag99gkb/7tPgUpT7o7ifuMAu2aODrq/b19b39fc919f95b569a187f1ddf66ec0/image3.png
https://cf-assets.www.cloudflare.com/zkvhlag99gkb/6Qb588RBcnkgWlTyqpP1gF/9b582d0a766be5e200b4a608a5fc2ee0/image7.png

Status: ✓ Verified


## B.3 — Imperva Bad Bot Report — opsiyonel
- URL: https://www.imperva.com/resources/resource-library/reports/
- Year: 2024/2025
- Verified: 2026-05-04

Bot Evasion Tactics
Evasion in the Age of AI-Driven Automation
Based on insights from Thales Security Analyst Services and Threat Research, the following evasion
tactics were most prevalent in 2025:
AI-Assisted Evasion and Learned Adaptation. AI is used to analyze application workflows, refine attack logic,
and rapidly adjust behavior when blocked. Analysts observed bots adapting within hours of mitigation deployment.
AI-driven iteration enables attackers to test defensive responses and refine tactics at speed.
CAPTCHA Solving at Scale. AI-assisted solving has weakened traditional CAPTCHA controls, but human CAPTCHA
farms have not disappeared. Many services now blend AI with incentivized human solvers, enabling bots to bypass
challenges at scale while increasing friction for legitimate users.
Privacy Tools. Capabilities such as iCloud Private Relay obscure user identity, making it more difficult to distinguish
between genuine user activity and automated bot traffic.
Adaptive Polymorphic Behavior. Modern bots continuously modify timing, request sequencing, and infrastructure.
Rather than relying on a fixed approach, they adapt dynamically in response to mitigation controls, making
persistence a defining characteristic of automated attacks.
Advanced Fingerprinting and Identity Evasion. Bots increasingly present valid, consistent browser identities that
closely mirror real users. Analysts observed dynamic fingerprint manipulation across headers, device attributes, and
execution patterns. In more advanced cases, bots leveraged token reuse, as well as cookie and session ID reuse from
legitimate sessions to bypass controls.
API-First Attack Execution. Bots increasingly bypass front-end interfaces and interact directly with authentication,
search, booking, and payment APIs. These requests are often well-formed and authenticated, allowing attackers to
operate at machine speed while avoiding traditional web-layer controls.
Infrastructure Masking Through Proxies. The use of residential and mobile proxy networks remains highly
effective. By routing traffic through legitimate user devices and ISP networks, bots blend into normal geographic
and behavioral patterns, reducing the effectiveness of IP-based detection.
Headless and Automation Frameworks. Tools such as Puppeteer, Selenium and Playwright remain widely used,
now enhanced with AI-generated scripting and real-time behavioral tuning. These tools enable bots to execute
JavaScript, maintain session state, and replicate multi-step user journeys.
Bots as a Service Platforms. The commercialization of bot capabilities continues to expand. Service-based
platforms offering scraping and scalping at scale, often enhanced with AI-driven refinement
Multi-Threaded and Persistent Attack Models. Bots increasingly operating through parallel threads or fallback
mechanisms. When one attack vector was mitigated, activity continues through lower noise channels making
persistence a defining tactic.

Bots Impersonating Browsers
To avoid detection, bad bots frequently disguise themselves
as legitimate web or mobile browsers commonly used by
real users to bypass basic security controls.
Chrome continues to be the browser most impersonated by
attackers. In 2025, 41 percent of bad bot traffic declared
itself as Chrome, up slightly from 39 percent in 2024.
Android Browser remained the second most impersonated
browser at 17 percent, reflecting the continued importance
of mobile traffic as a disguise for automated attacks.

BOTS IMPERSONATING
BROWSERS 2025 VS 2024
BROWSER 2024 2025

Chrome 39% 41%
Android Browser 17% 17%
Firefox 11% 10%
Internet Explorer 12% 9%
Mobile Safari 7% 9%
Safari 5% 6%
Mobile Chrome 4% 4%
Microsoft Edge 4% 3%
Opera 1% 1%
Samsung Browser 0.2% 0.14%
UCBrowser 0.18% 0.09%
When bots are indistinguishable from human traffic, traditional detection breaks down 

The Most Common Attack Types
This chart highlights the most common attack types targeting websites, applications, and APIs, showing
how automation has become a major driver of modern cyber threats. The largest category is general
automation which could include brute force automated attacks, or vulnerability scanning, where bots
are used to probe systems, test credentials, scrape data, or repeatedly exploit weaknesses at scale,
accounting for 29 percent of activity.

GENERAL AUTOMATION 29%
API VIOLATION 24%
BUSINESS LOGIC 21 %
PATH TRAVERSAL/LFI 9%
DATA LEAKAGE 5%
RCE/RFI 4%
XSS 4%
SQLi
PROTOCOL MANIPULATION 1%
OTHER 2%

The data also shows that business logic abuse (21percent) is a major threat. In these attacks, bots
manipulate legitimate application workflows.
API violations (24 percent) are another significant category, including issues such as broken
authorization or mass assignment that allow attackers to access data or functionality they shouldn’t.
API violations are often OWASP API Top Ten threats including: Broken Object Level Authorization
(BOLA) or Unrestricted Access to Sensitive Business Flows.
Attack Sophistication
In 2025, advanced bot attacks (44 percent) and moderate bot attacks (14 percent) accounted for a
combined total of 58 percent of all bot attacks, a 2-percentage point increase on the previous year.
Bad bots became more adaptive and persistent, leveraging AI to mutate fingerprints, adjust interaction
timing, and pivot rapidly when mitigations were applied. Security Analyst teams frequently observed
campaigns that returned repeatedly, probing different endpoints and workflows until a viable path
was found.
Simple bot attacks also prevailed in 2025, accounting for 42 percent of all attacks (dropping from
44 percent in 2024). However, the volume of simple bot attacks increased by more than 230%
compared to 2024, driven by AI lowering the barrier to entry and enabling attackers with limited
expertise to deploy automation at scale. While individually unsophisticated, simple bot attacks
contributed to sustained infrastructure load and operational noise.
The interaction between these two types of attack produced a compounding effect. High-volume
simple bots created constant background pressure, while advanced and moderate bots, targeted
high-value workflows such as authentication, booking, checkout, and payments. Rather than short
attack spikes, many organizations experienced continuous bot presence, effectively sharing their
infrastructure with automated agents over extended periods.

Key Findings in Numbers
42%
Simple bot attacks
41%
the percentage of bot
attacks using Chrome to
appear as legitimate traffic
24%
The percentage of bot
attacks targeting
Financial Services sites
47%
Percentage of
internet traffic
attributed to
human traffic
27%
Bot attacks targeting APIs
46% 
The percentage of account takeover

Status: ✓ Verified
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

