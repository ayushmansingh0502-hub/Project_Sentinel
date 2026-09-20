"""
Unit tests for geo_intel.py (Feature 3.2 Origin Traceability & GeoLocation)
"""
import unittest
from geo_intel import resolve_origin, is_private_ip, is_trusted_mta, flag_anonymization

class TestGeoIntel(unittest.TestCase):

    def test_private_ip_detection(self):
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertTrue(is_private_ip("10.0.4.12"))
        self.assertTrue(is_private_ip("172.16.0.5"))
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertFalse(is_private_ip("185.220.101.5"))
        self.assertFalse(is_private_ip("203.0.113.195"))

    def test_trusted_mta_detection(self):
        self.assertTrue(is_trusted_mta("mail.internal.company.com"))
        self.assertTrue(is_trusted_mta("trusted-mta.security.net"))
        self.assertFalse(is_trusted_mta("mail.unknown-spammer.org"))

    def test_tor_and_anonymization_flagging(self):
        flags = flag_anonymization("185.220.101.5", "Tor Exit Node Network", "AS24940")
        self.assertTrue(flags["is_tor"])
        self.assertTrue(flags["is_hosting"])

        flags_clean = flag_anonymization("203.0.113.195", "NTT Communications", "AS2914")
        self.assertFalse(flags_clean["is_tor"])
        self.assertFalse(flags_clean["is_vpn"])

    def test_bottom_up_origin_resolution(self):
        # Relay chain ordered from sender (index 0) to final receiver (index 2)
        chain = [
            {"ip": "10.0.0.2", "domain": "sender-client.local"},          # Private IP -> Skip
            {"ip": "185.220.101.5", "domain": "mail.anonymous-exit.org"}, # Public TOR exit node -> PROBABLE ORIGIN
            {"ip": "198.51.100.42", "domain": "relay-us.mta.net"},         # Public intermediate relay
            {"ip": "172.16.1.100", "domain": "mail-relay.internal"}       # Trusted internal MTA -> Skip
        ]

        origin, hops = resolve_origin(chain)

        self.assertEqual(origin.ip, "185.220.101.5")
        self.assertTrue(origin.is_tor)
        self.assertEqual(len(hops), 4)
        self.assertEqual(origin.country, "Germany")

if __name__ == "__main__":
    unittest.main()
