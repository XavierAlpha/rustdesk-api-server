from django.test import SimpleTestCase, override_settings

from webui2.views import (
    _normalize_relay_server,
    _normalize_rendezvous_server,
    _resolve_webui2_servers,
)


class WebClientServerConfigurationTests(SimpleTestCase):
    @override_settings(
        DEFAULT_ID_PORT=21116,
        ID_SERVER="id.example.com",
        RELAY_SERVER="",
    )
    def test_native_endpoints_use_service_ports(self):
        raw, rendezvous, relay = _resolve_webui2_servers()

        self.assertEqual(raw, ["id.example.com"])
        self.assertEqual(rendezvous, ["id.example.com:21116"])
        self.assertEqual(relay, ["id.example.com:21117"])

    @override_settings(
        DEFAULT_ID_PORT=21116,
        ID_SERVER="ws://id.example.com",
        RELAY_SERVER="",
    )
    def test_plain_websocket_endpoints_use_websocket_ports(self):
        _raw, rendezvous, relay = _resolve_webui2_servers()

        self.assertEqual(rendezvous, ["ws://id.example.com:21118"])
        self.assertEqual(relay, ["ws://id.example.com:21119"])

    @override_settings(
        DEFAULT_ID_PORT=21116,
        ID_SERVER="wss://remote.example.com:443",
        RELAY_SERVER="",
    )
    def test_tls_reverse_proxy_uses_one_origin_and_distinct_paths(self):
        _raw, rendezvous, relay = _resolve_webui2_servers()

        self.assertEqual(
            rendezvous,
            ["wss://remote.example.com:443/ws/id"],
        )
        self.assertEqual(
            relay,
            ["wss://remote.example.com:443/ws/relay"],
        )

    @override_settings(
        DEFAULT_ID_PORT=21116,
        ID_SERVER="wss://remote.example.com:8443/custom-id?tenant=one",
        RELAY_SERVER="wss://relay.example.com:9443/custom-relay?tenant=one",
    )
    def test_explicit_proxy_paths_and_queries_are_preserved(self):
        _raw, rendezvous, relay = _resolve_webui2_servers()

        self.assertEqual(
            rendezvous,
            ["wss://remote.example.com:8443/custom-id?tenant=one"],
        )
        self.assertEqual(
            relay,
            ["wss://relay.example.com:9443/custom-relay?tenant=one"],
        )

    @override_settings(DEFAULT_ID_PORT=21116)
    def test_invalid_or_credentialed_endpoints_are_rejected(self):
        self.assertEqual(_normalize_rendezvous_server("https://id.example.com"), "")
        self.assertEqual(
            _normalize_rendezvous_server("wss://user:secret@id.example.com"),
            "",
        )
        self.assertEqual(
            _normalize_relay_server("relay.example.com/path"),
            "",
        )
