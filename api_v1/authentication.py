import os

from rest_framework import authentication, exceptions


class ApiAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        if not request.headers.get('Api-key') or request.headers.get('Api-key') != os.environ.get('API_KEY'):

            raise exceptions.AuthenticationFailed('Missing api key')
