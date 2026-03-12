from django.urls import path
from auth_token.config import settings as auth_token_settings

from .views import OauthMsCallback, OauthMsLogin, SamlMsCallback, SamlMsLogin


urlpatterns = [
    path(
        f'{auth_token_settings.MS_SSO_BASE_URL}/mso',
        OauthMsLogin.as_view(),
        name='ms-sso-login',
    ),
    path(
        f'{auth_token_settings.MS_SSO_BASE_URL}/mso/callback',
        OauthMsCallback.as_view(),
        name='ms-sso-redirect',
    ),
    path(
        f'{auth_token_settings.MS_SSO_BASE_URL}/mso/saml',
        SamlMsLogin.as_view(),
        name='ms-sso-saml-login',
    ),
    path(
        f'{auth_token_settings.MS_SSO_BASE_URL}/mso/saml/callback',
        SamlMsCallback.as_view(),
        name='ms-sso-saml-redirect',
    ),
]
