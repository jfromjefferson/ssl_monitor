import ssl
from datetime import datetime

import OpenSSL
from django.core.handlers.wsgi import WSGIRequest
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from rest_framework import serializers

from api_v1.models import SysUser


def get_owner(request: WSGIRequest):
    sys_user = get_object_or_404(SysUser, uuid=request.headers.get('Sys-user-uuid'))

    return sys_user.owner


def get_error_dict(serializer: serializers.ModelSerializer, status_code: int = None):
    error_dict = {}

    for key, value in serializer.errors.items():
        error_dict[key] = value[0]

    error_dict['status_code'] = status_code if status_code else 200

    return JsonResponse(error_dict, status=status_code if status_code else 200)


def response_message(message_dict: dict):
    response = JsonResponse(message_dict)

    response.status_code = message_dict.get('status_code')

    return response


def certificate_info(hostname: str) -> [bool, dict]:
    success = True

    try:
        hostname_temp = hostname.split('//')[1]
        cert = ssl.get_server_certificate((hostname_temp, 443))

        cert_data = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

        cert_data_dict = {
            'subject': f'{format_certificate_info(cert_data.get_subject().get_components())} www.{format_certificate_info(cert_data.get_subject().get_components())}',
            'issuer': format_certificate_info(cert_data.get_issuer().get_components()),
            'cert_valid_from': datetime.strptime(cert_data.get_notBefore().decode(), '%Y%m%d%H%M%SZ').strftime('%Y-%m-%d %H:%M'),
            'cert_valid_until': datetime.strptime(cert_data.get_notAfter().decode(), '%Y%m%d%H%M%SZ').strftime('%Y-%m-%d %H:%M'),
            'cert_version': cert_data.get_version(),
            'cert_has_expired': cert_data.has_expired(),
        }

        # extensions = (cert_data.get_extension(i) for i in range(cert_data.get_extension_count()))
        # extension_data = {e.get_short_name(): str(e) for e in extensions}
        # cert_data_dict.update(extension_data)

        return success, cert_data_dict
    except Exception as error:
        success = False
        error_dict = {
            'message': str(error),
            'status_code': 400
        }

        return success, error_dict


def format_certificate_info(info: list):
    formatted_info = ''

    for info_temp in info:
        formatted_info += f'{info_temp[1]}, '

    return formatted_info.replace('b', '').replace("'", '')
