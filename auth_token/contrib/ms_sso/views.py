from django.contrib import messages
from django.contrib.auth import authenticate
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import ImproperlyConfigured
from django.http import Http404, HttpResponseRedirect
from django.http import response as http_response
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import RedirectView, View

from auth_token.config import settings
from auth_token.utils import login

from .helpers import Protocol, acquire_token_by_auth_code_flow, get_sign_in_flow, init_saml_auth


# Longest URL Django accepts in a redirect response (older Django releases do not define the constant).
MAX_REDIRECT_URL_LENGTH = getattr(http_response, 'MAX_URL_REDIRECT_LENGTH', 2048)

DEFAULT_NEXT_URL = '/'


def _get_safe_next_url(next_url):
    """
    Return next URL only if it is a relative path on the current site with an acceptable length, otherwise "/".
    Prevents open redirect attack (https://cwe.mitre.org/data/definitions/601.html) and redirects which
    Django refuses to send.
    """
    if (
        isinstance(next_url, str)
        and next_url.startswith('/')
        and len(next_url) <= MAX_REDIRECT_URL_LENGTH
        and url_has_allowed_host_and_scheme(next_url, allowed_hosts=None)
    ):
        return next_url
    return DEFAULT_NEXT_URL


def _check_session(request):
    if not hasattr(request, 'session'):
        raise ImproperlyConfigured('Django SessionMiddleware must be enabled to use MS SSO')


class ProtocolCheckMixin:

    def dispatch(self, request, *args, **kwargs):
        if self.protocol != Protocol(settings.MS_SSO_PROTOCOL):
            raise Http404
        return super().dispatch(request, *args, **kwargs)


class OauthMsLogin(ProtocolCheckMixin, RedirectView):

    protocol = Protocol.OAUTH

    def get_redirect_url(self, *args, **kwargs):
        sign_flow = get_sign_in_flow()
        sign_flow['next'] = _get_safe_next_url(self.request.GET.get('next'))

        _check_session(self.request)
        self.request.session['auth_token_ms_sso_auth_flow'] = sign_flow
        return sign_flow['auth_uri']


class SamlMsLogin(ProtocolCheckMixin, RedirectView):

    protocol = Protocol.SAML

    def get_redirect_url(self, *args, **kwargs):
        auth = init_saml_auth(self.request)
        url = auth.login(return_to=_get_safe_next_url(self.request.GET.get('next')))
        if len(url) > MAX_REDIRECT_URL_LENGTH:
            # Next URL is sent to the identity provider as a query parameter, too long one is replaced with default
            url = auth.login(return_to=DEFAULT_NEXT_URL)
        return url


class BaseMsCallback(ProtocolCheckMixin, View):

    allowed_cookie = True
    allowed_header = False

    def _get_next(self):
        return DEFAULT_NEXT_URL

    def _redirect_to_login_with_error(self):
        messages.error(
            self.request, gettext('Microsoft SSO login was unsuccessful, please use another login method')
        )
        return redirect_to_login(self._get_next())

    def _do_login(self, **kwargs):
        user = authenticate(self.request, **kwargs)
        if not user:
            return self._redirect_to_login_with_error()
        else:
            login(
                self.request,
                user,
                allowed_cookie=self.allowed_cookie,
                allowed_header=self.allowed_header,
                two_factor_login=False
            )
            return HttpResponseRedirect(self._get_next())


class OauthMsCallback(BaseMsCallback):

    protocol = Protocol.OAUTH

    def _get_next(self):
        return _get_safe_next_url(self.sign_flow.get('next')) if self.sign_flow else super()._get_next()

    def get(self, *args, **kwargs):
        _check_session(self.request)
        self.sign_flow = self.request.session.get('auth_token_ms_sso_auth_flow')
        if not self.sign_flow:
            return self._redirect_to_login_with_error()

        result = acquire_token_by_auth_code_flow(self.sign_flow, self.request.GET)
        if 'access_token' not in result:
            return self._redirect_to_login_with_error()

        return self._do_login(mso_token=result['access_token'])


@method_decorator(csrf_exempt, name='dispatch')  # POST request from external service, we must disable CSRF
class SamlMsCallback(BaseMsCallback):

    protocol = Protocol.SAML

    def _get_next(self):
        return _get_safe_next_url(self.request.POST.get('RelayState'))

    def post(self, *args, **kwargs):
        return self._do_login(using_saml=True)
