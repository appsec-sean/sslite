import ssl, socket, re
from http.client import HTTPSConnection
from time import strftime, localtime, time

class sslScanner:
    #Create an sslScanner object with sslScanner("host_name", port_number)
    #Main methods are sslScanner.validate_hostname() and sslScanner.do_scan()
    #sslScanner.validate_hostname() returns Boolean
    #sslScanner.do_scan() returns dict
    #sslScanner.do_scan() calls self.validate_hostname() as part of normal operation
    
    def __init__(self, target_url, port):
        self.target_url = target_url
        self.port = port
    
    def validate_hostname(self):
        if len(self.target_url) > 255:
            return False
        if self.target_url[-1] == ".":
            self.target_url = self.target_url[:-1]
        allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(x) for x in self.target_url.split("."))
    
    def get_https_response(self):
        try:
            conn = HTTPSConnection(self.target_url + ":" + str(self.port))
            conn.request("GET", "/")
        except:
            raise Exception("Failed to establish the initial HTTPS connection at location '/' - perhaps the target URL doesn't exist")
        return conn.getresponse()
    
    def create_ssl_context(self):
        context = ssl.create_default_context()
        context.options &= ~ssl.OP_NO_SSLv3
        context.options &= ~ssl.OP_NO_SSLv2
        return context
    
    def update_ssl_context(self, context, ciphers):
        context.set_ciphers(ciphers)
    
    def wrap_socket_and_connect(self, context):
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=self.target_url)
        try:
            conn.connect((self.target_url, self.port))
        except TimeoutError:
            raise Exception("Failed to complete scan - our connections may have been rejected due to rate-limiting")
        return conn
    
    def connect_default_socket(self):
        context = self.create_ssl_context()
        try:
            conn = self.wrap_socket_and_connect(context)
        except ssl.CertificateError:
            raise Exception("Target URL's certificate is invalid!")
        try:
            conn.do_handshake()
        except:
            raise Exception("Failed to complete scan - our connections may have been rejected due to rate-limiting")
        return conn
    
    def connect_custom_socket(self, index, bulk_ciphers):
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        if index == 0:
            conn = ssl.wrap_socket(sock=sock, ssl_version=ssl.PROTOCOL_SSLv3, ciphers=bulk_ciphers)
        elif index == 1:
            conn = ssl.wrap_socket(sock=sock, ssl_version=ssl.PROTOCOL_TLSv1, ciphers=bulk_ciphers)
        elif index == 2:
            conn = ssl.wrap_socket(sock=sock, ssl_version=ssl.PROTOCOL_TLSv1_1, ciphers=bulk_ciphers)
        elif index == 3:
            conn = ssl.wrap_socket(sock=sock, ssl_version=ssl.PROTOCOL_TLSv1_2, ciphers=bulk_ciphers)
        else:
            raise Exception("Internal server error")
        try:
            conn.connect((self.target_url, self.port))
        except:
            raise Exception("Failed to complete scan - our connections may have been rejected due to rate-limiting")
        return conn
    
    def do_scan(self):
        ciphers = ['ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-SHA384', 'ECDHE-ECDSA-AES256-SHA384', 'ECDHE-RSA-AES256-SHA', 'ECDHE-ECDSA-AES256-SHA', 'DH-DSS-AES256-GCM-SHA384', 'DHE-DSS-AES256-GCM-SHA384', 'DH-RSA-AES256-GCM-SHA384', 'DHE-RSA-AES256-GCM-SHA384', 'DHE-RSA-AES256-SHA256', 'DHE-DSS-AES256-SHA256', 'DH-RSA-AES256-SHA256', 'DH-DSS-AES256-SHA256', 'DHE-RSA-AES256-SHA', 'DHE-DSS-AES256-SHA', 'DH-RSA-AES256-SHA', 'DH-DSS-AES256-SHA', 'DHE-RSA-CAMELLIA256-SHA', 'DHE-DSS-CAMELLIA256-SHA', 'DH-RSA-CAMELLIA256-SHA', 'DH-DSS-CAMELLIA256-SHA', 'ECDH-RSA-AES256-GCM-SHA384', 'ECDH-ECDSA-AES256-GCM-SHA384', 'ECDH-RSA-AES256-SHA384', 'ECDH-ECDSA-AES256-SHA384', 'ECDH-RSA-AES256-SHA', 'ECDH-ECDSA-AES256-SHA', 'AES256-GCM-SHA384', 'AES256-SHA256', 'AES256-SHA', 'CAMELLIA256-SHA', 'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-SHA256', 'ECDHE-ECDSA-AES128-SHA256', 'ECDHE-RSA-AES128-SHA', 'ECDHE-ECDSA-AES128-SHA', 'DH-DSS-AES128-GCM-SHA256', 'DHE-DSS-AES128-GCM-SHA256', 'DH-RSA-AES128-GCM-SHA256', 'DHE-RSA-AES128-GCM-SHA256', 'DHE-RSA-AES128-SHA256', 'DHE-DSS-AES128-SHA256', 'DH-RSA-AES128-SHA256', 'DH-DSS-AES128-SHA256', 'DHE-RSA-AES128-SHA', 'DHE-DSS-AES128-SHA', 'DH-RSA-AES128-SHA', 'DH-DSS-AES128-SHA', 'DHE-RSA-SEED-SHA', 'DHE-DSS-SEED-SHA', 'DH-RSA-SEED-SHA', 'DH-DSS-SEED-SHA', 'DHE-RSA-CAMELLIA128-SHA', 'DHE-DSS-CAMELLIA128-SHA', 'DH-RSA-CAMELLIA128-SHA', 'DH-DSS-CAMELLIA128-SHA', 'ECDH-RSA-AES128-GCM-SHA256', 'ECDH-ECDSA-AES128-GCM-SHA256', 'ECDH-RSA-AES128-SHA256', 'ECDH-ECDSA-AES128-SHA256', 'ECDH-RSA-AES128-SHA', 'ECDH-ECDSA-AES128-SHA', 'AES128-GCM-SHA256', 'AES128-SHA256', 'AES128-SHA', 'SEED-SHA', 'CAMELLIA128-SHA', 'ECDHE-RSA-RC4-SHA', 'ECDHE-ECDSA-RC4-SHA', 'ECDH-RSA-RC4-SHA', 'ECDH-ECDSA-RC4-SHA', 'RC4-SHA', 'RC4-MD5', 'ECDHE-RSA-DES-CBC3-SHA', 'ECDHE-ECDSA-DES-CBC3-SHA', 'EDH-RSA-DES-CBC3-SHA', 'EDH-DSS-DES-CBC3-SHA', 'DH-RSA-DES-CBC3-SHA', 'DH-DSS-DES-CBC3-SHA', 'ECDH-RSA-DES-CBC3-SHA', 'ECDH-ECDSA-DES-CBC3-SHA', 'DES-CBC3-SHA', 'NULL-MD5', 'NULL-SHA', 'IDEA-CBC-SHA', 'ADH-RC4-MD5', 'ADH-DES-CBC3-SHA', 'ADH-AES128-SHA', 'ADH-AES256-SHA', 'ADH-CAMELLIA128-SHA', 'ADH-CAMELLIA256-SHA', 'ADH-SEED-SHA', 'GOST94-GOST89-GOST89', 'GOST2001-GOST89-GOST89', 'GOST94-NULL-GOST94', 'GOST2001-NULL-GOST94', 'DHE-DSS-RC4-SHA', 'ECDHE-RSA-NULL-SHA', 'ECDHE-ECDSA-NULL-SHA', 'AECDH-NULL-SHA', 'AECDH-RC4-SHA', 'AECDH-DES-CBC3-SHA', 'AECDH-AES128-SHA', 'AECDH-AES256-SHA', 'NULL-SHA256', 'ADH-AES128-SHA256', 'ADH-AES256-SHA256', 'ADH-AES128-GCM-SHA256', 'ADH-AES256-GCM-SHA384', 'AES128-CCM', 'AES256-CCM', 'DHE-RSA-AES128-CCM', 'DHE-RSA-AES256-CCM', 'AES128-CCM8', 'AES256-CCM8', 'DHE-RSA-AES128-CCM8', 'DHE-RSA-AES256-CCM8', 'ECDHE-ECDSA-AES128-CCM', 'ECDHE-ECDSA-AES256-CCM', 'ECDHE-ECDSA-AES128-CCM8', 'ECDHE-ECDSA-AES256-CCM8', 'ECDHE-ECDSA-CAMELLIA128-SHA256', 'ECDHE-ECDSA-CAMELLIA256-SHA384', 'ECDHE-RSA-CAMELLIA128-SHA256', 'ECDHE-RSA-CAMELLIA256-SHA384', 'ECDHE-RSA-CHACHA20-POLY1305', 'ECDHE-ECDSA-CHACHA20-POLY1305', 'DHE-RSA-CHACHA20-POLY1305']
        openssl_ciphers = 'ALL:eNULL:!SRP:!PSK'
        valid = self.validate_hostname()
        if not valid:
            raise Exception("Target URL did not pass validation checks - remove https:// if you hadn't already")
        timestamp = localtime()
        scan_date = strftime("%a, %d %b %Y %H:%M:%S", timestamp)
        start_time_epoch = time()
        initial_response = self.get_https_response()  
        if initial_response.version == 10:
            response_version = "HTTP/1.0"
        elif initial_response.version == 11:
            response_version = "HTTP/1.1"
        else:
            response_version = "Err: couldn't identify"
        headers = initial_response.getheaders()
        has_server_sig = False
        has_hsts = False
        has_xframeoptions = False
        has_xxssprotection = False
        has_xcontenttypeoptions = False
        for i in range(0, len(headers)):
            if headers[i][0] == "Server":
                server_signature = headers[i][1]
                has_server_sig = True
            elif headers[i][0] == "Strict-Transport-Security":
                hsts_policy = headers[i][1]
                has_hsts = True
            elif headers[i][0] == "X-Frame-Options":
                xframeoptions = headers[i][1]
                has_xframeoptions = True
            elif headers[i][0] == "X-XSS-Protection":
                xxssprotection = headers[i][1]
                has_xxssprotection = True
            elif headers[i][0] == "X-Content-Type-Options":
                xcontenttypeoptions = headers[i][1]
                has_xcontenttypeoptions = True
        if not has_server_sig:
            server_signature = "Server signature not provided"
        if not has_hsts:
            hsts_policy = "HTTP Strict Transport Security (HSTS) not deployed"
        if not has_xframeoptions:
            xframeoptions = "X-Frame-Options header not provided"
        if not has_xxssprotection:
            xxssprotection = "X-XSS-Protection not deployed"
        if not has_xcontenttypeoptions:
            xcontenttypeoptions = "X-Content-Type-Options header not provided"
        ssl_sock = self.connect_default_socket()
        comp = ssl_sock.compression()
        if str(type(comp)) != "<class 'NoneType'>":
            comp_enabled = "Enabled"
        else:
            comp_enabled = "Disabled"
        conn1 = self.wrap_socket_and_connect(self.create_ssl_context())
        cert = conn1.getpeercert()
        conn1.close()
        try:
            issuer = cert['issuer'][len(cert['issuer']) - 1][0][1]
        except:
            issuer = "No issuer information given"
        try:
            if str(type(cert['crlDistributionPoints'])) == "<class 'tuple'>":
                crl_distribution_points = cert['crlDistributionPoints'][0]
            else:
                crl_distribution_points = cert['crlDistributionPoints']
        except KeyError:
            crl_distribution_points = "CRLs not supported"
        try:
            ocsp_responder = cert['OCSP']
        except:
            ocsp_responder = "OCSP not supported"
        try:
            cert_valid_until = cert['notAfter']
        except:
            cert_valid_until = "No expiry date!!!"
        supported_versions = []
        suites = []
        for i in range(0,4):
            try:
                conn2 = self.connect_custom_socket(i, openssl_ciphers)
                supported_versions.append(conn2.version())
                suites.append(conn2.cipher()[0])
            except:
                pass
        conn2.close()
        tls_versions = []
        for i in range(0, len(supported_versions)):
            tls_versions.append([supported_versions[i],suites[i]])
        suites = []
        ordered_suites = []
        unsupported = []
        context = self.create_ssl_context()
        for i in range(0, len(ciphers)):
            try:
                try:
                    self.update_ssl_context(context, ciphers[i])
                except ssl.SSLError:
                    unsupported.append(ciphers[i])
                conn3 = self.wrap_socket_and_connect(context)
                suites.append(ciphers[i])
            except (TimeoutError, ssl.SSLError, ssl.CertificateError):
                pass
        conn3.close()
        for i in range(0, len(suites) - 1):
            cipherlist = ""
            for j in range(0, len(suites) - 1):
                cipherlist = cipherlist + suites[j] + ", "
            cipherlist = cipherlist + suites[len(suites) - 1]
            self.update_ssl_context(context, cipherlist)
            conn4 = self.wrap_socket_and_connect(context)
            ordered_suites.append(conn4.cipher()[0])
            suites.remove(conn4.cipher()[0])
        ordered_suites.append(suites[0])
        conn4.close()
        time_taken = time() - start_time_epoch
        
        results = {
            'target_url': self.target_url,
            'scan_date': scan_date,
            'time_zone': 'UTC',
            'http_response_code': "%d %s" % (initial_response.status, initial_response.reason),
            'http_version': response_version,
            'server_signature': server_signature,
            'hsts_policy': hsts_policy,
            'x_frame_options': xframeoptions,
            'x_xss_protection': xxssprotection,
            'x_content_type_options': xcontenttypeoptions,
            'local_ip': ssl_sock.getsockname()[0],
            'local_port': str(ssl_sock.getsockname()[1]),
            'remote_ip': ssl_sock.getpeername()[0],
            'remote_port': str(ssl_sock.getpeername()[1]),
            'tls_compression': comp_enabled,
            'tls_versions': tls_versions,
            'cert_issuer': issuer,
            'cert_crl': crl_distribution_points,
            'cert_ocsp': ocsp_responder,
            'cert_expiry': cert_valid_until,
            'ordered_ciphers': ordered_suites,
            'untested_ciphers': unsupported,
            'test_duration': "%.2f" % (time_taken),
        }
        return results
