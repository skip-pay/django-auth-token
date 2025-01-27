import time
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import override_settings
from django.test.client import RequestFactory
from django.utils.timezone import localtime, now

import httpretty
import responses
from freezegun import freeze_time
from germanium.test_cases.client import ClientTestCase
from germanium.tools import assert_equal, assert_false, assert_is_none, assert_not_equal, assert_true

from auth_token.config import settings
from auth_token.contrib.ms_sso.backends import OauthMsSsoBackend
from auth_token.contrib.ms_sso.helpers import get_ms_sso_login_url, get_user_data, init_saml_auth

from .base import BaseTestCaseMixin


__all__ = (
    'OauthMsSsoTestCase',
    'SamlMsSsoTestCase',
)


class OauthMsSsoTestCase(BaseTestCaseMixin, ClientTestCase):

    def test_get_user_data_should_return_none_for_invalid_ms_response(self):
        with responses.RequestsMock() as resp:
            resp.add(
                responses.GET, 'https://graph.microsoft.com/v1.0/me', status=401,
                content_type='application/json', json={
                    'error': {
                        'code': 'InvalidAuthenticationToken',
                        'message': 'Access token is empty.',
                        'innerError': {
                            'date': '2022-12-28T12:39:11',
                            'request-id': '373332eb-b369-4577-8c1b-62c075a22926',
                            'client-request-id': '373332eb-b369-4577-8c1b-62c075a22926'
                        }
                    }
                }
            )
            assert_is_none(get_user_data('token'))

    def test_get_user_data_should_return_user_data(self):
        with responses.RequestsMock() as resp:
            user_data = {
               'displayName': 'Adele Vance',
               'mail': 'AdeleV@contoso.onmicrosoft.com',
               'userPrincipalName': 'AdeleV@contoso.onmicrosoft.com',
               'id': '87d349ed-44d7-43e1-9a83-5f2406dee5bd'
            }
            resp.add(
                responses.GET, 'https://graph.microsoft.com/v1.0/me', status=200,
                content_type='application/json', json=user_data
            )
            assert_equal(get_user_data('token'), user_data)

    def test_ms_sso_backend_should_not_authenticate_not_logged_user(self):
        with responses.RequestsMock() as resp:
            resp.add(responses.GET, 'https://graph.microsoft.com/v1.0/me', status=401, content_type='application/json')
            assert_is_none(OauthMsSsoBackend().authenticate(None, 'token'))

    def test_ms_sso_backend_should_return_none_for_none_token(self):
        assert_is_none(OauthMsSsoBackend().authenticate(None, None))

    def test_ms_sso_backend_should_return_none_for_not_existing_user(self):
        with responses.RequestsMock() as resp:
            user_data = {
                'displayName': 'Test Test',
                'mail': 'test@localhost',
                'userPrincipalName': 'test',
                'id': '87d349ed-44d7-43e1-9a83-5f2406dee5bd'
            }
            resp.add(
                responses.GET, 'https://graph.microsoft.com/v1.0/me', status=200,
                content_type='application/json', json=user_data
            )
            assert_is_none(OauthMsSsoBackend().authenticate(None, 'token'))

    def test_ms_sso_backend_should_return_the_right_user(self):
        user = self.create_user()
        with responses.RequestsMock() as resp:
            user_data = {
                'displayName': 'Test Test',
                'mail': 'test@localhost',
                'userPrincipalName': 'test',
                'id': '87d349ed-44d7-43e1-9a83-5f2406dee5bd'
            }
            resp.add(
                responses.GET, 'https://graph.microsoft.com/v1.0/me', status=200,
                content_type='application/json', json=user_data
            )
            assert_equal(OauthMsSsoBackend().authenticate(None, 'token'), user)

    def test_login_mso_callback_should_log_user(self):
        user = self.create_user()
        with patch('auth_token.contrib.ms_sso.views.get_sign_in_flow') as mocked_get_sign_in_flow:
            mocked_get_sign_in_flow.return_value = {
                'state': 'state',
                'redirect_uri': None,
                'scope': ['openid', 'profile', 'user.read', 'offline_access'],
                'auth_uri': 'https://login.microsoftonline.com/test/oauth2/v2.0/authorize',
                'code_verifier': 'testverifier',
                'nonce': 'testnonce',
                'claims_challenge': None
            }
            response = self.get('/login/mso')
            assert_equal(response.status_code, 302)
            assert_equal(response['location'], 'https://login.microsoftonline.com/test/oauth2/v2.0/authorize')
            with patch('auth_token.contrib.ms_sso.views.acquire_token_by_auth_code_flow') \
                    as mocked_acquire_token_by_auth_code_flow:
                mocked_acquire_token_by_auth_code_flow.return_value = {
                    'access_token': 'token'
                }
                with responses.RequestsMock() as resp:
                    user_data = {
                        'displayName': 'Test Test',
                        'mail': 'test@localhost',
                        'userPrincipalName': 'test',
                        'id': '87d349ed-44d7-43e1-9a83-5f2406dee5bd'
                    }
                    resp.add(
                        responses.GET, 'https://graph.microsoft.com/v1.0/me', status=200,
                        content_type='application/json', json=user_data
                    )
                    response = self.get('/login/mso/callback')
                    assert_equal(response.wsgi_request.user, user)
                    assert_equal(response.status_code, 302)
                    assert_equal(response['location'], '/')

    def test_login_mso_callback_without_access_token_should_not_log_user(self):
        with patch('auth_token.contrib.ms_sso.views.get_sign_in_flow') as mocked_get_sign_in_flow:
            mocked_get_sign_in_flow.return_value = {
                'state': 'state',
                'redirect_uri': None,
                'scope': ['openid', 'profile', 'user.read', 'offline_access'],
                'auth_uri': 'https://login.microsoftonline.com/test/oauth2/v2.0/authorize',
                'code_verifier': 'testverifier',
                'nonce': 'testnonce',
                'claims_challenge': None
            }
            response = self.get('/login/mso')
            assert_equal(response.status_code, 302)
            assert_equal(response['location'], 'https://login.microsoftonline.com/test/oauth2/v2.0/authorize')
            with patch('auth_token.contrib.ms_sso.views.acquire_token_by_auth_code_flow') \
                    as mocked_acquire_token_by_auth_code_flow:
                mocked_acquire_token_by_auth_code_flow.return_value = {}
                response = self.get('/login/mso/callback')
                assert_false(response.wsgi_request.user.is_authenticated)
                assert_equal(response.status_code, 302)
                assert_equal(response['location'], '/accounts/login/?next=/')

    def test_login_mso_callback_without_sign_flow_should_not_log_user(self):
        response = self.get('/login/mso/callback')
        assert_false(response.wsgi_request.user.is_authenticated)
        assert_equal(response.status_code, 302)
        assert_equal(response['location'], '/accounts/login/?next=/')

    def test_get_ms_sso_login_url_should_return_correct_url_for_oauth(self):
        assert_equal(get_ms_sso_login_url(), '/login/mso')

    @override_settings(AUTH_TOKEN_MS_SSO_PROTOCOL='saml')
    def test_endpoints_for_oauth_should_return_404_if_this_protocol_is_not_set(self):
        assert_equal(self.c.get('/login/mso').status_code, 404)
        assert_equal(self.c.get('/login/mso/callback').status_code, 404)


@override_settings(AUTH_TOKEN_MS_SSO_PROTOCOL='saml')
@override_settings(AUTH_TOKEN_MS_SSO_SAML_METADATA_URL='http://localhost/metadata')
@override_settings(AUTH_TOKEN_MS_SSO_SAML_ENTITY_ID='My Test App')
class SamlMsSsoTestCase(BaseTestCaseMixin, ClientTestCase):

    def _get_auth_mock(self):
        auth_mock = MagicMock()
        auth_mock.get_nameid.return_value = 'john@doe.com'
        auth_mock.get_last_message_id.return_value = '123'
        auth_mock.get_last_assertion_id.return_value = '456'
        auth_mock.get_last_assertion_not_on_or_after.return_value = int(time.time()) + 3600  # valid for 1 hour
        return auth_mock

    def _register_metadata_url(self, httpretty):
        with open('dj/apps/app/tests/saml_metadata_response.xml', 'r') as f:
            saml_metadata_response = f.read()

        httpretty.register_uri(
            httpretty.GET,
            'http://localhost/metadata',
            status=200,
            content_type='application/xml',
            body=saml_metadata_response,
        )

    @httpretty.activate  # we cannot use responses, becuase python3-saml uses urllib, not requests
    def test_saml_should_log_in_user(self):
        CACHE_KEY = 'django_auth_token_saml_message_123_456'
        user = self.create_user(username='john@doe.com')

        self._register_metadata_url(httpretty)

        # verify we're redirected to the identity provider
        response = self.get('/login/mso/saml?next=/dashboard')
        assert_equal(response.status_code, 302)
        assert_true(response['location'].startswith(
            'https://login.microsoftonline.com/54311acb-4c14-4e2a-ba36-fcd4de0bffa2/saml2'
        ))

        # POST payload is dynamic and signed, not easy to mock, therefore we mock auth object instead
        with patch('auth_token.contrib.ms_sso.backends.init_saml_auth') as init_mock:
            init_mock.return_value = self._get_auth_mock()
            response = self.post('/login/mso/saml/callback', data={'RelayState': ['/dashboard']})
            assert_equal(response.status_code, 302)
            assert_equal(response['location'], '/dashboard')
            assert_equal(response.wsgi_request.user, user)
            assert_true(response.wsgi_request.user.is_authenticated)
            assert_true(cache.get(CACHE_KEY))

            # logout user
            user.authorization_tokens.all().delete()

            # repeated request (replay attack) 1 second before timeout, must not succeed
            with freeze_time(localtime() + timedelta(minutes=59, seconds=59), tick=True):
                response = self.post('/login/mso/saml/callback', data={'RelayState': ['/dashboard']})
                assert_equal(response.status_code, 302)
                assert_equal(response['location'], '/accounts/login/?next=/dashboard')
                assert_not_equal(response.wsgi_request.user, user)
                assert_false(response.wsgi_request.user.is_authenticated)
                assert_true(cache.get(CACHE_KEY))

            # after timeout, cache entry is evicted
            with freeze_time(localtime() + timedelta(minutes=60), tick=True):
                assert_false(cache.get(CACHE_KEY))

        # cleanup
        cache.delete(CACHE_KEY)

    def test_saml_should_not_log_in_user(self):
        self.create_user(username='alice@doe.com')
        self.create_user(username='john@doe.com', is_active=False)
        for user in User.objects.all():
            with patch('auth_token.contrib.ms_sso.backends.SamlMsSsoBackend._get_natural_key') as mock:
                mock.return_value = 'john@doe.com'
                response = self.post('/login/mso/saml/callback', data={'RelayState': ['/dashboard']})
                assert_equal(response.status_code, 302)
                assert_equal(response['location'], '/accounts/login/?next=/dashboard')
                assert_not_equal(response.wsgi_request.user, user)
                assert_false(response.wsgi_request.user.is_authenticated)

    def test_get_ms_sso_login_url_should_return_correct_url_for_saml(self):
        assert_equal(get_ms_sso_login_url(), '/login/mso/saml')

    @override_settings(AUTH_TOKEN_MS_SSO_PROTOCOL='oauth')
    def test_endpoints_for_saml_should_return_404_if_this_protocol_is_not_set(self):
        assert_equal(self.c.get('/login/mso/saml').status_code, 404)
        assert_equal(self.c.get('/login/mso/saml/callback').status_code, 404)

    def test_saml_should_prevent_open_redirect_attack(self):
        user = self.create_user(username='john@doe.com')
        with patch('auth_token.contrib.ms_sso.backends.SamlMsSsoBackend._get_natural_key') as mock:
            mock.return_value = 'john@doe.com'
            response = self.post('/login/mso/saml/callback', data={'RelayState': ['http://example.com/dashboard']})
            assert_equal(response.status_code, 302)
            assert_equal(response['location'], '/')  # absolute URL is ignored, fallback to '/'
            assert_equal(response.wsgi_request.user, user)
            assert_true(response.wsgi_request.user.is_authenticated)

    @httpretty.activate
    def test_saml_auth_should_be_correctly_initialized(self):
        self._register_metadata_url(httpretty)
        auth = init_saml_auth(RequestFactory().get('/'))
        service_provider_settings = auth._settings._sp
        assert_equal(service_provider_settings['entityId'], 'My Test App')
        assert_equal(
            service_provider_settings['assertionConsumerService']['url'],
            'http://testserver/login/mso/saml/callback',
        )
        security_settings = auth._settings._security
        assert_equal(security_settings['requestedAuthnContext'], False)
