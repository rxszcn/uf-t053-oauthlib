# -*- coding: utf-8 -*-
"""Cross-grant matrix for duplicate request parameter handling.

RFC 6749 section 3.2 requires that request and response parameters MUST NOT
be included more than once at the token endpoint. Every token endpoint grant
type must therefore reject a duplicated protected parameter with the same
error (``invalid_request``), the same status code (400) and the same JSON
response shape, regardless of how the client authenticated itself.
"""
import json
from unittest import mock

from oauthlib.common import Request
from oauthlib.oauth2 import (
    BackendApplicationServer, LegacyApplicationServer, RequestValidator,
    WebApplicationServer,
)
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from oauthlib.oauth2.rfc8628.grant_types import DeviceCodeGrant

from tests.unittest import TestCase


TOKEN_URI = 'https://i.b/token'


class DuplicateParameterMatrixTest(TestCase):
    """Every token endpoint grant rejects duplicate parameters identically."""

    def setUp(self):
        self.validator = mock.MagicMock(spec=RequestValidator)

        def set_client(request):
            request.client = mock.MagicMock()
            request.client.client_id = request.client_id or 'mocked'
            request.client_id = request.client.client_id
            return True

        # Confidential client authentication succeeds for both the
        # Authorization header and the client_id/client_secret body form.
        self.validator.authenticate_client.side_effect = set_client
        self.validator.client_authentication_required.return_value = True
        self.validator.get_original_scopes.return_value = ['foo', 'bar']
        self.validator.validate_refresh_token.return_value = True
        self.validator.validate_user.return_value = True
        self.validator.validate_grant_type.return_value = True
        self.validator.validate_scopes.return_value = True
        self.validator.is_within_original_scope.return_value = True

        self.web = WebApplicationServer(self.validator)
        self.legacy = LegacyApplicationServer(self.validator)
        self.backend = BackendApplicationServer(self.validator)
        self.device_grant = DeviceCodeGrant(self.validator)
        self.bearer = BearerToken(self.validator)

    # (entry label, grant_type, duplicated parameter, body without the
    # duplicated parameter, callable style). The duplicated parameter is
    # appended twice with identical values so no other validation can mask
    # the result.
    MATRIX = (
        # Refresh token grant: the grant type this hardening was missing on.
        ('refresh_token', 'refresh_token', 'grant_type',
         'grant_type=refresh_token&refresh_token=abc', 'server', 'web'),
        ('refresh_token', 'refresh_token', 'refresh_token',
         'grant_type=refresh_token&refresh_token=abc', 'server', 'web'),
        ('refresh_token', 'refresh_token', 'scope',
         'grant_type=refresh_token&refresh_token=abc', 'server', 'web'),
        # Authorization code grant.
        ('authorization_code', 'authorization_code', 'grant_type',
         'grant_type=authorization_code&code=foo', 'server', 'web'),
        ('authorization_code', 'authorization_code', 'client_id',
         'grant_type=authorization_code&code=foo&client_id=abcdef',
         'server', 'web'),
        ('authorization_code', 'authorization_code', 'redirect_uri',
         ('grant_type=authorization_code&code=foo'
          '&redirect_uri=https%3A%2F%2Fi.b%2Fcb'), 'server', 'web'),
        # Resource owner password credentials grant.
        ('password', 'password', 'grant_type',
         'grant_type=password&username=foo&password=baz', 'server', 'legacy'),
        ('password', 'password', 'username',
         'grant_type=password&username=foo&password=baz', 'server', 'legacy'),
        ('password', 'password', 'password',
         'grant_type=password&username=foo&password=baz', 'server', 'legacy'),
        ('password', 'password', 'scope',
         'grant_type=password&username=foo&password=baz', 'server', 'legacy'),
        # Client credentials grant.
        ('client_credentials', 'client_credentials', 'grant_type',
         'grant_type=client_credentials', 'server', 'backend'),
        ('client_credentials', 'client_credentials', 'scope',
         'grant_type=client_credentials', 'server', 'backend'),
        # Device authorization grant (RFC 8628), driven at grant level as it
        # has no standalone pre-configured token endpoint server.
        ('device_code',
         'urn:ietf:params:oauth:grant-type:device_code', 'grant_type',
         ('grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code'
          '&device_code=dev123'), 'grant', 'device_grant'),
        ('device_code',
         'urn:ietf:params:oauth:grant-type:device_code', 'scope',
         ('grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code'
          '&device_code=dev123'), 'grant', 'device_grant'),
    )

    def _body_with_duplicate(self, base_body, param, grant_type):
        value = grant_type if param == 'grant_type' else 'dup'
        return '%s&%s=%s&%s=%s' % (base_body, param, value, param, value)

    def _invoke(self, style, target_attr, body, headers):
        if style == 'server':
            return getattr(self, target_attr).create_token_response(
                TOKEN_URI, body=body, headers=headers)
        request = Request(TOKEN_URI, body=body, headers=headers)
        return getattr(self, target_attr).create_token_response(
            request, self.bearer)

    def _assert_duplicate_rejected(self, style, target_attr, body, param,
                                   headers):
        resp_headers, response_body, status_code = self._invoke(
            style, target_attr, body, headers)
        payload = json.loads(response_body)
        self.assertEqual(status_code, 400)
        self.assertEqual(payload['error'], 'invalid_request')
        self.assertEqual(payload['error_description'],
                         'Duplicate %s parameter.' % param)
        self.assertEqual(resp_headers['Content-Type'], 'application/json')
        self.assertEqual(resp_headers['Cache-Control'], 'no-store')
        self.assertEqual(resp_headers['Pragma'], 'no-cache')
        self.validator.save_token.assert_not_called()

    def test_duplicate_params_rejected_by_every_grant(self):
        for label, grant_type, param, base_body, style, target_attr \
                in self.MATRIX:
            body = self._body_with_duplicate(base_body, param, grant_type)
            with self.subTest(grant_type=label, param=param,
                              client_auth='basic_header'):
                self.validator.reset_mock()
                self._assert_duplicate_rejected(
                    style, target_attr, body, param,
                    {'Authorization': 'abcdef:secret'})

    def test_duplicate_params_rejected_with_body_client_credentials(self):
        # Client identity carried in the request body instead of the
        # Authorization header must see the same rejection.
        for label, grant_type, param, base_body, style, target_attr \
                in self.MATRIX:
            body = self._body_with_duplicate(
                '%s&client_id=abcdef&client_secret=secret' % base_body,
                param, grant_type)
            with self.subTest(grant_type=label, param=param,
                              client_auth='request_body'):
                self.validator.reset_mock()
                self._assert_duplicate_rejected(
                    style, target_attr, body, param, {})

    def test_refresh_grant_single_value_still_succeeds(self):
        # Non-regression: a well-formed single-value refresh request still
        # gets a new token with either client authentication mechanism.
        body = 'grant_type=refresh_token&refresh_token=abc&scope=foo'

        self.validator.reset_mock()
        _headers, response_body, status_code = \
            self.web.create_token_response(
                TOKEN_URI, body=body,
                headers={'Authorization': 'abcdef:secret'})
        self.assertEqual(status_code, 200, response_body)
        token = json.loads(response_body)
        self.assertIn('access_token', token)
        self.assertEqual(self.validator.save_token.call_count, 1)

        self.validator.reset_mock()
        _headers, response_body, status_code = \
            self.web.create_token_response(
                TOKEN_URI,
                body='%s&client_id=abcdef&client_secret=secret' % body)
        self.assertEqual(status_code, 200, response_body)
        token = json.loads(response_body)
        self.assertIn('access_token', token)
        self.assertEqual(self.validator.save_token.call_count, 1)

    def test_refresh_grant_duplicate_rejected_before_authentication(self):
        # The duplicate parameter check precedes client authentication, as
        # in the other grant types, so no credential verification runs.
        body = ('grant_type=refresh_token&refresh_token=abc'
                '&refresh_token=abc')
        self.validator.reset_mock()
        _h, response_body, status_code = self.web.create_token_response(
            TOKEN_URI, body=body,
            headers={'Authorization': 'abcdef:secret'})
        self.assertEqual(status_code, 400)
        self.assertEqual(json.loads(response_body)['error'], 'invalid_request')
        self.validator.authenticate_client.assert_not_called()
        self.validator.save_token.assert_not_called()
