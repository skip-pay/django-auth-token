from enum import Enum

from django.conf import settings as django_settings
from django.urls import reverse

import msal
import requests
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

from auth_token.config import settings


graph_url = 'https://graph.microsoft.com/v1.0'


class Protocol(Enum):
    OAUTH = 'oauth'
    SAML = 'saml'


def get_user_data(token):
    response = requests.get(
        f'{graph_url}/me',
        headers={'Authorization': f'Bearer {token}'},
        params={'$select': 'displayName,mail,userPrincipalName'}
    )
    if response.status_code == 200:
        return response.json()
    else:
        return None


def get_msal_app():
    """
    Initialize the MSAL confidential client
    """
    return msal.PublicClientApplication(
        settings.MS_SSO_APP_ID,
        authority=f'https://login.microsoftonline.com/{settings.MS_SSO_TENANT_ID}'
    )


def get_sign_in_flow():
    """
    Method to generate a sign-in flow
    """
    return get_msal_app().initiate_auth_code_flow(['user.read'])


def acquire_token_by_auth_code_flow(sign_flow, data):
    """
    Method to get auth code from sign flow and request data
    """
    return get_msal_app().acquire_token_by_auth_code_flow(sign_flow, data)


def parse_request_for_saml(request):
    """
    Inspired from the example project:
    https://github.com/SAML-Toolkits/python3-saml/blob/v1.16.0/demo-django/demo/views.py#L17
    """
    return {
        'https': 'on' if request.is_secure() else 'off',
        'http_host': request.get_host(),
        'script_name': request.get_full_path(),
        'get_data': request.GET.copy(),
        'post_data': request.POST.copy(),
    }


def init_saml_auth(request):
    service_provider_settings = {
        'strict': True,
        'debug': django_settings.DEBUG,
        'security': {
            'requestedAuthnContext': False,  # do not enforce any particular authentication method
            **({'allowSingleLabelDomains': True} if getattr(django_settings, "AUTH_TOKEN_TEST", False) else {}),
        },
        'sp': {
            'entityId': settings.MS_SSO_SAML_ENTITY_ID,
            'assertionConsumerService': {
                'url': request.scheme + '://' + request.get_host() + reverse('ms-sso-saml-redirect'),
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            },
        },
    }
    identity_provider_settings = OneLogin_Saml2_IdPMetadataParser.parse_remote(settings.MS_SSO_SAML_METADATA_URL)
    merged_settings = OneLogin_Saml2_IdPMetadataParser.merge_settings(
        service_provider_settings,
        identity_provider_settings,
    )
    return OneLogin_Saml2_Auth(parse_request_for_saml(request), merged_settings)


def get_ms_sso_login_url():
    protocol = Protocol(settings.MS_SSO_PROTOCOL)
    if protocol == Protocol.OAUTH:
        return reverse('ms-sso-login')
    elif protocol == Protocol.SAML:
        return reverse('ms-sso-saml-login')
