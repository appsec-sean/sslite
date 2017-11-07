# sslite
A lightweight class for checking SSL/TLS configuration, written in Python v3.


##### Info #####
Has a hard dependency on OpenSSL.

The .do_scan() function will attempt to make one connection for each available client cipher suite, and it will re-test the ones that are accepted to determine priority order. Therefore the number of connections made is limited by your installation of OpenSSL, with a maximum theoretical limit of ~200 connections.

By default, the .do_scan() function will attempt to make all of these connections as fast as possible, so request-limiting controls may cause exceptions to be thrown.

Scans only function correctly when a URL is given and that URL is resolvable using your system's configured DNS servers.
##### ----- #####


#####  Example Usage #####
```
(appsecenv) user@vm01:~/appsecenv/appsecproject$ python manage.py shell
Python 3.5.2 (default, Nov 17 2016, 17:05:23) 
[GCC 5.4.0 20160609] on linux
Type "help", "copyright", "credits" or "license" for more information.
(InteractiveConsole)
```
```python
>>> import crypto.sslite as sslite
>>> scan_obj = sslite.sslScanner("example.com", 443)
>>> scan_obj.validate_hostname()
True
>>> results = scan_obj.do_scan()
>>> for i in results:
...     print(i + ": ", results[i])
...
```
```
local_port:  56760
scan_date:  Mon, 06 Nov 2017 23:45:55
ordered_ciphers:  ['ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES256-GCM-SHA384', 'DHE-RSA-AES128-GCM-SHA256', 'DHE-RSA-AES256-GCM-SHA384']
cert_issuer:  Go Daddy Secure Certificate Authority - G2
http_response_code:  200 OK
cert_ocsp:  ('http://ocsp.godaddy.com/',)
cert_crl:  http://crl.godaddy.com/gdig2s1-691.crl
x_xss_protection:  1; mode=block
hsts_policy:  max-age=31536000; includeSubdomains
test_duration:  24.36
remote_port:  443
time_zone:  UTC
server_signature:  nginx
untested_ciphers:  ['IDEA-CBC-SHA', 'GOST94-GOST89-GOST89', 'GOST2001-GOST89-GOST89', 'GOST94-NULL-GOST94', 'GOST2001-NULL-GOST94', 'DHE-DSS-RC4-SHA', 'AES128-CCM', 'AES256-CCM', 'DHE-RSA-AES128-CCM', 'DHE-RSA-AES256-CCM', 'AES128-CCM8', 'AES256-CCM8', 'DHE-RSA-AES128-CCM8', 'DHE-RSA-AES256-CCM8', 'ECDHE-ECDSA-AES128-CCM', 'ECDHE-ECDSA-AES256-CCM', 'ECDHE-ECDSA-AES128-CCM8', 'ECDHE-ECDSA-AES256-CCM8', 'ECDHE-ECDSA-CAMELLIA128-SHA256', 'ECDHE-ECDSA-CAMELLIA256-SHA384', 'ECDHE-RSA-CAMELLIA128-SHA256', 'ECDHE-RSA-CAMELLIA256-SHA384', 'ECDHE-RSA-CHACHA20-POLY1305', 'ECDHE-ECDSA-CHACHA20-POLY1305', 'DHE-RSA-CHACHA20-POLY1305']
tls_versions:  [['TLSv1.2', 'ECDHE-RSA-AES128-GCM-SHA256']]
x_content_type_options:  nosniff
local_ip:  192.168.126.131
target_url:  example.com
http_version:  HTTP/1.1
cert_expiry:  Jul 24 20:43:38 2018 GMT
remote_ip:  192.168.125.100
tls_compression:  Disabled
x_frame_options:  DENY
```
##### ----- #####


##### Known Issues #####

Returns ssl.CertificateError if you are located behind a Wi-Fi captive portal with no internet access (rather than TimeoutError).

Cannot reliably identify SSLv2 (due to inherent lack of support in modern OpenSSL implementations).

No testing for the current drafts of TLSv1.3.

If a server is not configured to use its own preference of cipher, results may be incorrect.
##### ----- #####


##### Upcoming Features #####

This section contains a list of desired and upcoming features for sslite.

+Identify when server is not set to prefer its own cipher list

+Identification of HTTP/2.0 and SPDY

+More in-depth validation of certificate (currently checks host trust store, if available)

+Level of support for older browsers

+Checks for certificate key length & signature algorithm (actually somewhat difficult to do...)

+Checks for key exchange parameter size

+Non-invasive mode (rate-limiting connections)
