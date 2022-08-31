
from rest_framework import authentication, exceptions
from ssl_monitor.settings import API_KEY


class ApiAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        if not request.headers.get('Api-key') or request.headers.get('Api-key') != API_KEY:

            raise exceptions.AuthenticationFailed('Missing api key')
