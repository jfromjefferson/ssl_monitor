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


def response_message(message_dict: dict, status_code: int):
    response = JsonResponse(message_dict)

    response.status_code = status_code

    return response
