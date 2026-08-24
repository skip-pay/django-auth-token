from auth_token.contrib.common.views import LoginView as _LoginView
from auth_token.contrib.common.views import LogoutView as _LogoutView
from auth_token.utils import login, logout
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import (
    AuthTokenSerializer, MobileAuthTokenSerializer, MobileAuthTokenRegisterSerializer
)


class LoginAuthToken(APIView):

    throttle_classes = ()
    permission_classes = ()
    authentication_classes = ()
    serializer_class = AuthTokenSerializer
    allowed_cookie = False
    allowed_header = True

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(
            request._request, user, preserve_cookie=not serializer.validated_data.get('permanent', False),
            allowed_cookie=self.allowed_cookie, allowed_header=self.allowed_header
        )
        return Response({'token': request._request.token.secret_key})


class MobileLoginAuthToken(APIView):

    throttle_classes = ()
    permission_classes = ()
    authentication_classes = ()
    serializer_class = MobileAuthTokenSerializer
    allowed_cookie = False
    allowed_header = True

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        login(
            request._request, user,
            allowed_cookie=self.allowed_cookie, allowed_header=self.allowed_header
        )
        return Response({'token': request._request.token.secret_key})


class LogoutAuthToken(APIView):

    def delete(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            logout(request._request)
        return Response(status=204)


class MobileRegisterToken(APIView):

    serializer_class = MobileAuthTokenRegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response({'device_login_token': serializer.validated_data['token']})


class LoginView(_LoginView):

    template_name = 'rest_framework_auth/login.html'


class LogoutView(_LogoutView):

    template_name = None

    def get_next_page(self):
        return super().get_next_page() or '/'
