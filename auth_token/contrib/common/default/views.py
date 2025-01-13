from urllib.parse import quote_plus

from django.contrib.auth.views import LoginView, LogoutView
from django.http import HttpResponseRedirect
from django.urls import NoReverseMatch
from django.utils.decorators import method_decorator
from django.utils.translation import gettext
from django.views.decorators.cache import never_cache

from auth_token.contrib.common.forms import TokenAuthenticationForm
from auth_token.contrib.ms_sso.helpers import get_ms_sso_login_url
from auth_token.utils import login, logout


class TokenLoginView(LoginView):

    form_class = TokenAuthenticationForm
    allowed_cookie = True
    allowed_header = False

    def get(self, request, *args, **kwargs):
        if self.request.user.is_authenticated:
            return HttpResponseRedirect(self.get_success_url())
        else:
            return super().get(request, *args, **kwargs)

    def _login(self, user, preserve_cookie, form):
        login(
            self.request, user, preserve_cookie=preserve_cookie,
            allowed_cookie=self.allowed_cookie, allowed_header=self.allowed_header
        )

    def form_valid(self, form):
        """
        The user has provided valid credentials (this was checked in AuthenticationForm.is_valid()). So now we
        can check the test cookie stuff and log him in.
        """
        self._login(form.get_user(), not form.is_permanent(), form)
        return HttpResponseRedirect(self.get_success_url())

    def _get_sso_login_methods(self):
        try:
            return [
                {
                    'name': 'microsoft',
                    'url': f'{get_ms_sso_login_url()}?next={quote_plus(self.request.GET.get("next", "/"), safe="/")}',
                    'label': gettext('Continue with Microsoft account')
                }
            ]
        except NoReverseMatch:
            return []

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['sso_login_methods'] = self._get_sso_login_methods()
        return context


class TokenLogoutView(LogoutView):

    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        logout(request)
        return super().dispatch(request, *args, **kwargs)


class InputLogMixin:

    def log_successful_request(self):
        pass

    def log_unsuccessful_request(self):
        pass
