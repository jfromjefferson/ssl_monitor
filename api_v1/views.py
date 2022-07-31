import json

from django.contrib.auth.models import User
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404

from rest_framework import viewsets

from api_v1.authentication import ApiAuthentication
from api_v1.models import SysUser, Owner
from api_v1.serializers import UserSerializer
from utils.functions import get_owner, response_message, get_error_dict


class UserConfigView(viewsets.ViewSet):
    authentication_classes = [ApiAuthentication]

    serializer_class = UserSerializer
    queryset = ''

    def create(self, request):
        serializer = UserSerializer(data=request.data)

        if serializer.is_valid():
            validated_data: dict = serializer.validated_data

            user_obj = User.objects.filter(username=validated_data.get('username')).first()

            if not user_obj:
                user = User.objects.create(
                    first_name=validated_data.get('first_name'),
                    last_name=validated_data.get('last_name'),
                    username=validated_data.get('username'),
                )

                user.set_password(raw_password=validated_data.get('password'))

                user.save()

                owner = Owner.objects.create(user=user)
                sys_user = SysUser.objects.create(
                    user=user,
                    owner=owner,
                )

                message_dict = {
                    'message': 'User info updated successfully.',
                    'status_code': 200,
                }

                return response_message(message_dict, status_code=message_dict.get('status_code'))
        else:
            error_dict = {}

            for key, value in serializer.errors.items():
                error_dict[key] = value[0]

            return JsonResponse(error_dict)

    def put(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data, partial=True)

        owner = get_owner(request)

        if serializer.is_valid():
            validated_data: dict = serializer.validated_data

            username = request.headers.get('Username')
            user = User.objects.filter(username=username).first()

            if user:
                user.first_name = validated_data.get('first_name')
                user.last_name = validated_data.get('last_name')
                user.set_password(validated_data.get('password'))

                user.save()

                sys_user: SysUser = owner.sysuser_set.first()

                message_dict = {
                    'message': 'User info updated successfully.',
                    'status_code': 200,
                }

                return response_message(message_dict, status_code=message_dict.get('status_code'))
            else:
                message_dict = {
                    'message': 'This user does not exists',
                    'status_code': 400
                }

                return response_message(message_dict, status_code=message_dict.get('status_code'))
        else:
            get_error_dict(serializer, status_code=400)

    def delete(self, request, pk=None):
        owner = get_owner(request)
        sys_user = get_object_or_404(SysUser, uuid=request.headers.get('Sys-user-uuid'), owner=owner)

        sys_user.user.delete()

        message_dict = {
            'message': 'User deleted successfully',
            'status_code': 200
        }

        return response_message(message_dict, status_code=message_dict.get('status_code'))
