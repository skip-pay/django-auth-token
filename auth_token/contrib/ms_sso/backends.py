import time

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.cache import cache

from auth_token.contrib.ms_sso.views import init_saml_auth

from .helpers import get_user_data


class BaseMsSsoBackend(ModelBackend):
    """
    Base class for MS SSO related backends.
    """

    user_model = get_user_model()

    def _get_natural_key(self):
        """
        This method should return user's identifier (e.g. e-mail) received from the identity provider.
        """
        raise NotImplementedError

    def _get_user_from_natural_key(self):
        try:
            return self.user_model._default_manager.get_by_natural_key(self._get_natural_key())
        except self.user_model.DoesNotExist:
            return None

    def authenticate(self, request, **kwargs):
        if (user := self._get_user_from_natural_key()) and self.user_can_authenticate(user):
            return user
        else:
            return None


class OauthMsSsoBackend(BaseMsSsoBackend):

    def _get_natural_key(self):
        return self.ms_user_data['userPrincipalName']

    def authenticate(self, request, mso_token, **kwargs):
        self.ms_user_data = get_user_data(mso_token)

        if not self.ms_user_data:
            return None

        return super().authenticate(request)


class SamlMsSsoBackend(BaseMsSsoBackend):

    def _get_natural_key(self):
        auth = init_saml_auth(self.request)
        auth.process_response()

        # To avoid replay attacks, check if the message was already processed
        cache_key = f'django_auth_token_saml_message_{auth.get_last_message_id()}_{auth.get_last_assertion_id()}'
        if cache.get(cache_key):
            return None
        cache.set(cache_key, True, timeout=auth.get_last_assertion_not_on_or_after() - int(time.time()))

        return auth.get_nameid()

    def authenticate(self, request, using_saml, **kwargs):
        self.request = request
        return super().authenticate(request)
