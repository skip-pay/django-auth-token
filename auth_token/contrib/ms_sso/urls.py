from django.urls import path

from .views import OauthMsCallback, OauthMsLogin, SamlMsCallback, SamlMsLogin


urlpatterns = [
    path(
        'internal-login/mso',
        OauthMsLogin.as_view(),
        name='ms-sso-login',
    ),
    path(
        'internal-login/mso/callback',
        OauthMsCallback.as_view(),
        name='ms-sso-redirect',
    ),
    path(
        'internal-login/mso/saml',
        SamlMsLogin.as_view(),
        name='ms-sso-saml-login',
    ),
    path(
        'internal-login/mso/saml/callback',
        SamlMsCallback.as_view(),
        name='ms-sso-saml-redirect',
    ),
]
