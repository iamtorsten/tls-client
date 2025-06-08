import base64
import ctypes
import os
import threading
import time
import urllib.parse
import uuid
from datetime import timedelta
from json import dumps, loads
from sys import platform
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urljoin

from .__version__ import __version__
from .cffi import addCookiesToSession, destroySession, freeMemory, getCookiesFromSession, request
from .cookies import cookiejar_from_dict, extract_cookies_to_jar, merge_cookies
from .exceptions import TLSClientExeption
from .response import Response, build_response
from .settings import ClientIdentifiers
from .structures import CaseInsensitiveDict

if platform == "win32":
    preferred_clock = time.perf_counter
else:
    preferred_clock = time.time


class SteamThread(threading.Thread):
    def __init__(self, main_request, target, **kwargs):
        super(SteamThread, self).__init__(daemon=True)
        self._stop_event = threading.Event()
        self.main_request = main_request
        self.target = target
        self.kwargs = kwargs

    def stop(self) -> None:
        self._stop_event.set()
        self.on_stop()

    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    def run(self) -> None:
        try:
            self.target(**self.kwargs)
        except Exception as e:
            self.on_error(e)
        finally:
            self.on_done()

    def on_stop(self) -> None:
        self.main_request.writing = False
        self._remove_file()

    def on_done(self) -> None:
        self.main_request.writing = False

    def on_error(self, error: Exception) -> None:
        self.main_request.writing = False
        print(f"An error occurred: {error}")

    def _remove_file(self) -> None:
        filepath = getattr(self.main_request, '_filepath', None)
        if filepath and os.path.exists(filepath):
            try:
                os.remove(filepath)
            except OSError as e:
                print(f"Error removing file {filepath}: {e}")


class Session:
    def __init__(self,
                 client_identifier: ClientIdentifiers = "chrome_124",
                 ja3_string: Optional[str] = None,
                 h2_settings: Optional[Dict[str, int]] = None,
                 h2_settings_order: Optional[List[str]] = None,
                 supported_signature_algorithms: Optional[List[str]] = None,
                 supported_delegated_credentials_algorithms: Optional[List[str]] = None,
                 supported_versions: Optional[List[str]] = None,
                 key_share_curves: Optional[List[str]] = None,
                 cert_compression_algo: str = None,
                 additional_decode: str = None,
                 pseudo_header_order: Optional[List[str]] = None,
                 connection_flow: Optional[int] = None,
                 priority_frames: Optional[list] = None,
                 header_order: Optional[List[str]] = None,
                 header_priority: Optional[List[str]] = None,
                 random_tls_extension_order: bool = False,
                 force_http1: bool = False,
                 catch_panics: bool = False,
                 debug: bool = False,
                 certificate_pinning: Optional[Dict[str, List[str]]] = None,
                 disable_ipv6: bool = False,
                 disable_ipv4: bool = False,
                 ) -> None:

        self.MAX_REDIRECTS: int = 30

        self._session_id = str(uuid.uuid4())
        # --- Standard Settings ----------------------------------------------------------------------------------------

        # Case-insensitive dictionary of headers, send on each request
        # self.headers = CaseInsensitiveDict(
        #     {
        #         "User-Agent": f"tls-client/{__version__}",
        #         "Accept-Encoding": "gzip, deflate, br",
        #         "Accept": "*/*",
        #         "Connection": "keep-alive",
        #     }
        # )
        self.headers = {}


        # Example:
        # {
        #     "http": "http://user:pass@ip:port",
        #     "https": "http://user:pass@ip:port"
        # }
        self.proxies = {}

        # Dictionary of querystring data to attach to each request. The dictionary values may be lists for representing
        # multivalued query parameters.
        self.params = {}

        # CookieJar containing all currently outstanding cookies set on this session
        self.cookies = cookiejar_from_dict({})

        # Timeout
        self.timeout = 30

        # Certificate pinning
        self.certificate_pinning = certificate_pinning

        # --- Advanced Settings ----------------------------------------------------------------------------------------

        # Examples:
        # Chrome --> chrome_103, chrome_104, chrome_105, chrome_106
        # Firefox --> firefox_102, firefox_104
        # Opera --> opera_89, opera_90
        # Safari --> safari_15_3, safari_15_6_1, safari_16_0
        # iOS --> safari_ios_15_5, safari_ios_15_6, safari_ios_16_0
        # iPadOS --> safari_ios_15_6
        #
        # for all possible client identifiers, check out the settings.py
        self.client_identifier = client_identifier

        # Set JA3 --> TLSVersion, Ciphers, Extensions, EllipticCurves, EllipticCurvePointFormats
        # Example:
        # 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0
        self.ja3_string = ja3_string

        # HTTP2 Header Frame Settings
        # Possible Settings:
        # HEADER_TABLE_SIZE
        # SETTINGS_ENABLE_PUSH
        # MAX_CONCURRENT_STREAMS
        # INITIAL_WINDOW_SIZE
        # MAX_FRAME_SIZE
        # MAX_HEADER_LIST_SIZE
        #
        # Example:
        # {
        #     "HEADER_TABLE_SIZE": 65536,
        #     "MAX_CONCURRENT_STREAMS": 1000,
        #     "INITIAL_WINDOW_SIZE": 6291456,
        #     "MAX_HEADER_LIST_SIZE": 262144
        # }
        self.h2_settings = h2_settings

        # HTTP2 Header Frame Settings Order
        # Example:
        # [
        #     "HEADER_TABLE_SIZE",
        #     "MAX_CONCURRENT_STREAMS",
        #     "INITIAL_WINDOW_SIZE",
        #     "MAX_HEADER_LIST_SIZE"
        # ]
        self.h2_settings_order = h2_settings_order

        # Supported Signature Algorithms
        # Possible Settings:
        # PKCS1WithSHA256
        # PKCS1WithSHA384
        # PKCS1WithSHA512
        # PSSWithSHA256
        # PSSWithSHA384
        # PSSWithSHA512
        # ECDSAWithP256AndSHA256
        # ECDSAWithP384AndSHA384
        # ECDSAWithP521AndSHA512
        # PKCS1WithSHA1
        # ECDSAWithSHA1
        #
        # Example:
        # [
        #     "ECDSAWithP256AndSHA256",
        #     "PSSWithSHA256",
        #     "PKCS1WithSHA256",
        #     "ECDSAWithP384AndSHA384",
        #     "PSSWithSHA384",
        #     "PKCS1WithSHA384",
        #     "PSSWithSHA512",
        #     "PKCS1WithSHA512",
        # ]
        self.supported_signature_algorithms = supported_signature_algorithms

        # Supported Delegated Credentials Algorithms
        # Possible Settings:
        # PKCS1WithSHA256
        # PKCS1WithSHA384
        # PKCS1WithSHA512
        # PSSWithSHA256
        # PSSWithSHA384
        # PSSWithSHA512
        # ECDSAWithP256AndSHA256
        # ECDSAWithP384AndSHA384
        # ECDSAWithP521AndSHA512
        # PKCS1WithSHA1
        # ECDSAWithSHA1
        #
        # Example:
        # [
        #     "ECDSAWithP256AndSHA256",
        #     "PSSWithSHA256",
        #     "PKCS1WithSHA256",
        #     "ECDSAWithP384AndSHA384",
        #     "PSSWithSHA384",
        #     "PKCS1WithSHA384",
        #     "PSSWithSHA512",
        #     "PKCS1WithSHA512",
        # ]
        self.supported_delegated_credentials_algorithms = supported_delegated_credentials_algorithms

        # Supported Versions
        # Possible Settings:
        # GREASE
        # 1.3
        # 1.2
        # 1.1
        # 1.0
        #
        # Example:
        # [
        #     "GREASE",
        #     "1.3",
        #     "1.2"
        # ]
        self.supported_versions = supported_versions

        # Key Share Curves
        # Possible Settings:
        # GREASE
        # P256
        # P384
        # P521
        # X25519
        #
        # Example:
        # [
        #     "GREASE",
        #     "X25519"
        # ]
        self.key_share_curves = key_share_curves

        # Cert Compression Algorithm
        # Examples: "zlib", "brotli", "zstd"
        self.cert_compression_algo = cert_compression_algo

        # Additional Decode
        # Make sure the go code decodes the response body once explicit by provided algorithm.
        # Examples: null, "gzip", "br", "deflate"
        self.additional_decode = additional_decode

        # Pseudo Header Order (:authority, :method, :path, :scheme)
        # Example:
        # [
        #     ":method",
        #     ":authority",
        #     ":scheme",
        #     ":path"
        # ]
        self.pseudo_header_order = pseudo_header_order

        # Connection Flow / Window Size Increment
        # Example:
        # 15663105
        self.connection_flow = connection_flow

        # Example:
        # [
        #   {
        #     "streamID": 3,
        #     "priorityParam": {
        #       "weight": 201,
        #       "streamDep": 0,
        #       "exclusive": false
        #     }
        #   },
        #   {
        #     "streamID": 5,
        #     "priorityParam": {
        #       "weight": 101,
        #       "streamDep": false,
        #       "exclusive": 0
        #     }
        #   }
        # ]
        self.priority_frames = priority_frames

        # Order of your headers
        # Example:
        # [
        #   "key1",
        #   "key2"
        # ]
        self.header_order = header_order

        # Header Priority
        # Example:
        # {
        #   "streamDep": 1,
        #   "exclusive": true,
        #   "weight": 1
        # }
        self.header_priority = header_priority

        # randomize tls extension order
        self.random_tls_extension_order = random_tls_extension_order

        # force HTTP1
        self.force_http1 = force_http1

        # catch panics
        # avoid the tls client to print the whole stacktrace when a panic (critical go error) happens
        self.catch_panics = catch_panics

        # disable ipv6/ipv4
        self.disable_ipv6 = disable_ipv6
        self.disable_ipv4 = disable_ipv4
        # debugging
        self.debug = debug

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __del__(self):
        self.close()

    def close(self) -> str:
        destroy_session_payload = {
            "sessionId": self._session_id
        }

        destroy_session_response = destroySession(dumps(destroy_session_payload).encode('utf-8'))
        destroy_session_response_bytes = ctypes.string_at(destroy_session_response)
        destroy_session_response_string = destroy_session_response_bytes.decode('utf-8')
        destroy_session_response_object = loads(destroy_session_response_string)
        freeMemory(destroy_session_response_object['id'].encode('utf-8'))
        # todo add exception if success is False
        return destroy_session_response_string

    def get_cookies_from_session(self, url: str) -> List[Dict[str, str]]:
        cookie_payload = {
            "sessionId": self._session_id,
            "url": url,
        }
        cookie_response = getCookiesFromSession(dumps(cookie_payload).encode('utf-8'))
        cookie_response_bytes = ctypes.string_at(cookie_response)
        cookie_response_string = cookie_response_bytes.decode('utf-8')
        cookie_response_object = loads(cookie_response_string)

        freeMemory(cookie_response_object['id'].encode('utf-8'))
        if cookie_response_object.get("status") == 0:
            raise TLSClientExeption(cookie_response_object["body"])

        return cookie_response_object["cookies"]

    def add_cookies_to_session(self, url: str, cookies: List[Dict[str, str]]) -> None:
        # https://bogdanfinn.gitbook.io/open-source-oasis/shared-library/payload#cookie-input
        cookies_payload = {
            "cookies": cookies,
            "sessionId": self._session_id,
            "url": url,
        }
        # todo add exception, no session
        add_cookies_to_session_response = addCookiesToSession(dumps(cookies_payload).encode('utf-8'))
        add_cookies_bytes = ctypes.string_at(add_cookies_to_session_response)
        add_cookies_string = add_cookies_bytes.decode('utf-8')
        add_cookies_object = loads(add_cookies_string)

        freeMemory(add_cookies_object['id'].encode('utf-8'))
        if add_cookies_object.get("status") == 0:
            raise TLSClientExeption(add_cookies_object["body"])

    @staticmethod
    def _prepare_url(url: str, params: Optional[Dict] = None) -> str:
        if params is not None:
            return f"{url}?{urllib.parse.urlencode(params, doseq=True)}"
        return url

    @staticmethod
    def _prepare_request_body(data: Optional[Union[str, dict]] = None,
                              json: Optional[Dict] = None
                              ) -> Tuple[Optional[str], Optional[str]]:
        if data is None and json is not None:
            if type(json) in [dict, list]:
                json = dumps(json)
            return json, "application/json"
        elif data is not None and type(data) not in [str, bytes]:
            return urllib.parse.urlencode(data, doseq=True), "application/x-www-form-urlencoded"
        return data, None

    def _merge_headers(self, headers: Optional[Dict] = None) -> CaseInsensitiveDict:
        if self.headers is None:
            return CaseInsensitiveDict(headers)
        elif headers is None:
            return self.headers.copy()
        else:
            merged_headers = self.headers.copy()
            merged_headers.update(headers)
            return CaseInsensitiveDict(merged_headers)

    def _prepare_cookies(self, cookies: Optional[Dict] = None) -> List[Dict[str, str]]:
        cookies = cookies or {}
        cookies = merge_cookies(self.cookies, cookies)
        return [
            {
                'domain': c.domain,
                'expires': c.expires,
                'name': c.name,
                'path': c.path,
                'value': c.value.replace('"', "")
            }
            for c in cookies
        ]

    def _get_proxy(self, proxy: Optional[Dict] = None, proxies: Optional[Dict] = None) -> str:
        proxy = proxy or proxies or self.proxies

        if isinstance(proxy, dict) and "http" in proxy:
            return proxy["http"]
        elif isinstance(proxy, str):
            return proxy
        else:
            return ""

    def _build_request_payload(self,
                               method: str,
                               url: str,
                               headers: CaseInsensitiveDict,
                               request_body: Optional[Union[str, bytes, bytearray]],
                               request_cookies: List[Dict],
                               is_byte_request: bool,
                               timeout: int,
                               proxy: str,
                               verify: bool,
                               stream: bool,
                               chunk_size: int,
                               certificate_pinning: Optional[Dict[str, List[str]]] = None
                               ) -> dict:

        # https://bogdanfinn.gitbook.io/open-source-oasis/shared-library/payload
        request_payload = {
            "additionalDecode": self.additional_decode,
            "catchPanics": self.catch_panics,
            # "certificatePinningHosts": None,
            # "customTlsClient": None,
            # "transportOptions": None,
            # "defaultHeaders": None,
            "disableIPV6": self.disable_ipv6,
            "disableIPV4": self.disable_ipv4,
            "followRedirects": False,
            "forceHttp1": self.force_http1,
            "headerOrder": self.header_order,
            "headers": dict(headers),
            "insecureSkipVerify": not verify,
            "isByteRequest": is_byte_request,
            "isByteResponse": True,
            "isRotatingProxy": False,
            "localAddress": None,
            "proxyUrl": proxy,
            "requestBody": base64.b64encode(request_body).decode() if is_byte_request else request_body,
            "requestCookies": request_cookies,
            "requestMethod": method,
            "requestUrl": url,
            "serverNameOverwrite": None,
            "sessionId": self._session_id,
            "streamOutputBlockSize": chunk_size,
            "streamOutputEOFSymbol": None,
            # "streamOutputPath": None,
            # "timeoutMilliseconds": 0,
            "timeoutSeconds": timeout,
            # "tlsClientIdentifier": "",
            "withDebug": self.debug,
            "withDefaultCookieJar": False,
            "withoutCookieJar": False,
            # "withRandomTLSExtensionOrder": False,
        }

        if stream and method != "HEAD":
            request_payload.update({"StreamOutputPath": os.path.join(os.getcwd(), self._session_id)})

        if certificate_pinning:
            request_payload["certificatePinningHosts"] = certificate_pinning

        if False:
            request_payload["transportOptions"] = {
                "disableCompression": False,
                "disableKeepAlives": False,
                "idleConnTimeout": 0,
                "maxConnsPerHost": 0,
                "maxIdleConns": 0,
                "maxIdleConnsPerHost": 0,
                "maxResponseHeaderBytes": 0,
                "readBufferSize": 0,
                "writeBufferSize": 0,
            }

        if self.client_identifier is None:
            request_payload["customTlsClient"] = {
                "ECHCandidateCipherSuites": None,
                "ECHCandidatePayloads": None,
                "alpnProtocols": None,
                "alpsProtocols": None,
                "certCompressionAlgo": self.cert_compression_algo,
                "connectionFlow": self.connection_flow,
                "h2Settings": self.h2_settings,
                "h2SettingsOrder": self.h2_settings_order,
                "headerPriority": self.header_priority,
                "ja3String": self.ja3_string,
                "keyShareCurves": self.key_share_curves,
                "priorityFrames": self.priority_frames,
                "pseudoHeaderOrder": self.pseudo_header_order,
                "supportedDelegatedCredentialsAlgorithms": self.supported_delegated_credentials_algorithms,
                "supportedSignatureAlgorithms": self.supported_signature_algorithms,
                "supportedVersions": self.supported_versions,
            }
        else:
            request_payload["tlsClientIdentifier"] = self.client_identifier
            request_payload["withRandomTLSExtensionOrder"] = self.random_tls_extension_order

        return request_payload

    def execute_request(
            self,
            method: str,
            url: str,
            params: Optional[Dict] = None,
            data: Optional[Union[str, dict]] = None,
            headers: Optional[Dict] = None,
            cookies: Optional[Dict] = None,
            json: Optional[Dict] = None,
            allow_redirects: Optional[bool] = True,
            verify: Optional[bool] = True,
            timeout: Optional[int] = None,
            proxy: Optional[Dict] = None,
            proxies: Optional[Dict] = None,
            stream: Optional[bool] = False,
            chunk_size: Optional[int] = 1024,
    ) -> Response:

        url = self._prepare_url(url, params)

        request_body, content_type = self._prepare_request_body(data, json)

        headers = self._merge_headers(headers)
        if content_type is not None:
            headers["Content-Type"] = content_type

        request_cookies = self._prepare_cookies(cookies)

        proxy = self._get_proxy(proxy, proxies)

        timeout = timeout or self.timeout

        certificate_pinning = self.certificate_pinning

        is_byte_request = isinstance(request_body, (bytes, bytearray))

        start = preferred_clock()

        history = []
        redirect = 0
        while True:
            request_payload = self._build_request_payload(
                method=method,
                url=url,
                headers=headers,
                request_body=request_body,
                request_cookies=request_cookies,
                is_byte_request=is_byte_request,
                timeout=timeout,
                proxy=proxy,
                verify=verify,
                stream=stream,
                chunk_size=chunk_size,
                certificate_pinning=certificate_pinning
            )

            # Execute the request using the TLS client
            response = request(dumps(request_payload).encode('utf-8'))
            response_bytes = ctypes.string_at(response)
            response_string = response_bytes.decode('utf-8')
            response_object = loads(response_string)
            freeMemory(response_object['id'].encode('utf-8'))

            # todo update for each Response
            elapsed = preferred_clock() - start

            # Handle response, split up into new method?
            if response_object["status"] == 0:
                raise TLSClientExeption(response_object["body"])

            response_cookie_jar = extract_cookies_to_jar(
                request_url=url,
                request_headers=headers,
                cookie_jar=self.cookies,
                response_headers=response_object["headers"]
            )

            if stream:
                filepath = os.path.join(os.getcwd(), self._session_id)
                response = build_response(response_object, response_cookie_jar, filepath)
            else:
                response = build_response(response_object, response_cookie_jar)
            response.elapsed = timedelta(seconds=elapsed)

            if not allow_redirects or not response.is_redirect:
                response.history = history
                return response

            history.append(response)
            redirect += 1

            if redirect > self.MAX_REDIRECTS:
                raise TLSClientExeption(f"Max redirects ({self.MAX_REDIRECTS}) exceeded")

            url = self._rebuild_url(url, response)
            method = self._rebuild_methods(method, response)

            if response.status_code not in (307, 308):
                request_body = None
                headers = self._rebuild_headers(headers)

    @staticmethod
    def _rebuild_methods(method: str, response: Response) -> str:
        if response.status_code == 303 and method != "HEAD":
            method = "GET"
        if response.status_code == 302 and method != "HEAD":
            method = "GET"
        if response.status_code == 301 and method != "POST":
            method = "GET"

        return method

    @staticmethod
    def _rebuild_url(url: str, response: Response) -> Optional[str]:
        url_redirect = response.headers.get("Location")
        if not url_redirect:
            return None
        return urljoin(url, url_redirect)

    @staticmethod
    def _rebuild_headers(headers: CaseInsensitiveDict) -> CaseInsensitiveDict:
        purged_headers = ("Content-Length", "Content-Type", "Transfer-Encoding")
        for header in purged_headers:
            headers.pop(header, None)
        return headers

    def get(self, url: str, **kwargs: Any) -> Response:
        """Sends a GET request"""
        if kwargs.get("stream", False):
            head_data = self.head(url, **kwargs)
            stream_data_thread = SteamThread(
                main_request=head_data,
                target=self.execute_request,
                method="GET",
                url=url,
                **kwargs
            )

            stream_data_thread.start()
            return head_data
        return self.execute_request(method="GET", url=url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> Response:
        """Sends a OPTIONS request"""
        return self.execute_request(method="OPTIONS", url=url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Response:
        """Sends a HEAD request"""
        kwargs.setdefault("allow_redirects", False)
        return self.execute_request(method="HEAD", url=url, **kwargs)

    def post(self, url: str, data: Optional[Union[str, dict]] = None, json: Optional[dict] = None, **kwargs: Any) -> Response:
        """Sends a POST request"""
        if kwargs.get("stream", False):
            # todo head for post request doesn't always work correctly
            head_data = self.head(url, allow_redircts=True, **kwargs)
            stream_data_thread = SteamThread(
                main_request=head_data,
                target=self.execute_request,
                method="POST",
                url=url,
                data=data,
                json=json,
                **kwargs
            )

            stream_data_thread.start()
            return head_data
        return self.execute_request(method="POST", url=url, data=data, json=json, **kwargs)

    def put(self, url: str, data: Optional[Union[str, dict]] = None, json: Optional[dict] = None, **kwargs: Any) -> Response:
        """Sends a PUT request"""
        return self.execute_request(method="PUT", url=url, data=data, json=json, **kwargs)

    def patch(self, url: str, data: Optional[Union[str, dict]] = None, json: Optional[dict] = None, **kwargs: Any) -> Response:
        """Sends a PATCH request"""
        return self.execute_request(method="PATCH", url=url, data=data, json=json, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> Response:
        """Sends a DELETE request"""
        return self.execute_request(method="DELETE", url=url, **kwargs)
