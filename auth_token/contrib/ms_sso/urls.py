from django.urls import path

from .views import OauthMsCallback, OauthMsLogin, SamlMsCallback, SamlMsLogin


urlpatterns = [
    path(
        'login/mso',
        OauthMsLogin.as_view(),
        name='ms-sso-login',
    ),
    path(
        'login/mso/callback',
        OauthMsCallback.as_view(),
        name='ms-sso-redirect',
    ),
    path(
        'login/mso/saml',
        SamlMsLogin.as_view(),
        name='ms-sso-saml-login',
    ),
    path(
        'login/mso/saml/callback',
        SamlMsCallback.as_view(),
        name='ms-sso-saml-redirect',
    ),
]
