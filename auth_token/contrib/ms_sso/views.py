from django.contrib import messages
from django.contrib.auth import authenticate
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import ImproperlyConfigured
from django.http import Http404, HttpResponseRedirect
from django.utils.decorators import method_decorator
from django.utils.translation import gettext
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import RedirectView, View

from auth_token.config import settings
from auth_token.utils import login

from .helpers import Protocol, acquire_token_by_auth_code_flow, get_sign_in_flow, init_saml_auth


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
        sign_flow['next'] = self.request.GET.get('next', '/')

        _check_session(self.request)
        self.request.session['auth_token_ms_sso_auth_flow'] = sign_flow
        return sign_flow['auth_uri']


class SamlMsLogin(ProtocolCheckMixin, RedirectView):

    protocol = Protocol.SAML

    def get_redirect_url(self, *args, **kwargs):
        return init_saml_auth(self.request).login(return_to=self.request.GET.get('next', '/'))


class BaseMsCallback(ProtocolCheckMixin, View):

    allowed_cookie = True
    allowed_header = False

    def _get_next(self):
        return '/'

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
        return self.sign_flow['next'] if self.sign_flow else super()._get_next()

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
        relay_state = self.request.POST.get('RelayState')
        # Test that value starts with "/" (relative redirect) to avoid open redirect attack.
        # See: https://cwe.mitre.org/data/definitions/601.html
        return relay_state if relay_state and relay_state.startswith('/') else super()._get_next()

    def post(self, *args, **kwargs):
        return self._do_login(using_saml=True)
