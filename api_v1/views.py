import json

from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404

from rest_framework import viewsets

from api_v1.authentication import ApiAuthentication
from api_v1.models import SysUser, Owner, Service
from api_v1.serializers import UserSerializer, ServiceSerializer
from utils.functions import get_owner, response_message, get_error_dict, certificate_info


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
                sys_user = SysUser.objects.create(user=user, owner=owner)

                message_dict = {
                    'message': 'User created successfully.',
                    'status_code': 200,
                    'sys_user_uuid': str(sys_user.uuid)
                }

                return response_message(message_dict)
        else:
            error_dict = {
                'status_code': 400
            }

            for key, value in serializer.errors.items():
                error_dict[key] = value[0]

            return response_message(error_dict)

    def put(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data, partial=True)

        get_owner(request)

        if serializer.is_valid():
            validated_data: dict = serializer.validated_data

            username = request.headers.get('Username')
            user = User.objects.filter(username=username).first()

            if user:
                user.first_name = validated_data.get('first_name')
                user.last_name = validated_data.get('last_name')
                user.set_password(validated_data.get('password'))

                user.save()

                message_dict = {
                    'message': 'User updated successfully.',
                    'status_code': 200,
                }

                return response_message(message_dict)
            else:
                message_dict = {
                    'message': 'This user does not exists',
                    'status_code': 400
                }

                return response_message(message_dict)
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

        return response_message(message_dict)


class ServiceConfigView(viewsets.ViewSet):
    authentication_classes = [ApiAuthentication]

    def create(self, request):
        serializer = ServiceSerializer(data=request.data)
        owner = get_owner(request)

        if serializer.is_valid():
            validated_data: dict = serializer.validated_data

            success, cert_dict = certificate_info(validated_data.get('url'))

            if success:
                ssl_properties = json.dumps(cert_dict)
                service_dict = {
                    'name': validated_data.get('name'),
                    'url': validated_data.get('url'),
                    'owner': owner,
                    'ssl_properties': ssl_properties
                }

                service: Service = serializer.save(**service_dict)

                del service_dict['owner']
                service_dict['uuid'] = str(service.uuid)
                service_dict['ssl_properties'] = json.loads(ssl_properties)

                message_dict = {
                    'message': 'Service created successfully',
                    'service_info': service_dict,
                    'status_code': 200,
                }

                return response_message(message_dict)
            else:
                return response_message(cert_dict)
        else:
            error_dict = {
                'status_code': 400
            }

            for key, value in serializer.errors.items():
                error_dict[key] = value[0]

            return response_message(error_dict)
