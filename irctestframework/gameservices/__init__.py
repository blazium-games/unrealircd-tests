"""Helpers for the Blazium third/gameservices module tests.

The module talks to the games API over HTTPS. mock_api.py stands in for that
API (and for the conduit websocket) so the suites under
tests/modules/gameservices_* can drive every module path without the real
service. The suites skip themselves when the module is not loaded.
"""
