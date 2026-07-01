from __future__ import annotations

import unittest

from adapter import SecurityHeadersAdapter, register_adapter, security_header_observations
from synapse_mcp.core.adapters import AdapterRegistry


class CustomAdapterTemplateTests(unittest.TestCase):
    def test_security_header_observation_creation(self) -> None:
        observations = security_header_observations(
            [
                {
                    "type": "endpoint",
                    "url": "https://example.com/",
                    "method": "GET",
                    "responseHeaders": {"Content-Type": "text/html"},
                }
            ]
        )

        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["type"], "security_headers_missing_candidate")
        self.assertIn("content-security-policy", observations[0]["missingHeaders"])

    def test_adapter_registration_and_plan(self) -> None:
        registry = AdapterRegistry()
        adapter = register_adapter(registry)

        self.assertIsInstance(adapter, SecurityHeadersAdapter)
        self.assertEqual(registry.capabilities("security_headers_template")["name"], "security_headers_template")
        self.assertEqual(registry.capabilities("security_headers_template")["executionMode"], "passive_only")
        self.assertFalse(adapter.plan({})["sendsTraffic"])


if __name__ == "__main__":
    unittest.main()
