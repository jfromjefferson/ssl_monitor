import json

from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404

from rest_framework import viewsets

from api_v1.authentication import ApiAuthentication
from api_v1.models import SysUser, Owner, Service
from api_v1.serializers import UserSerializer, ServiceSerializer, SysUserSerializer
from utils.functions import get_owner, response_message, get_error_dict, certificate_info
from utils.utils import CUSTOMER_PLAN_BASE


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
                    extra_info=json.dumps(CUSTOMER_PLAN_BASE)
                )

                message_dict = {
                    'message': 'User created successfully.',
                    'sys_user_uuid': str(sys_user.uuid),
                    'extra_info': CUSTOMER_PLAN_BASE,
                    'status_code': 200,
                }

                return response_message(message_dict)
        else:

            return get_error_dict(serializer, status_code=400)

    def put(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data, partial=True)

        success, owner = get_owner(request)

        if not success:
            return response_message(owner)

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
            return get_error_dict(serializer, status_code=400)

    def delete(self, request, pk=None):
        success, owner = get_owner(request)

        if not success:
            return response_message(owner)

        sys_user = get_object_or_404(SysUser, uuid=request.headers.get('Sys-user-uuid'), owner=owner)

        sys_user.user.delete()

        message_dict = {
            'message': 'User deleted successfully',
            'status_code': 200
        }

        return response_message(message_dict)


class SysUserConfigView(viewsets.ViewSet):
    authentication_classes = [ApiAuthentication]

    # TODO: Find a way to create only put method for this class
    def put(self, request, pk=None):
        serializer = SysUserSerializer(data=request.data, partial=True)
        success, owner = get_owner(request)

        if not success:
            return response_message(owner)

        if serializer.is_valid():
            message_dict = {
                'message': '',
                'status_code': 200
            }
            return response_message(message_dict)
        else:
            return get_error_dict(serializer, status_code=400)


class ServiceConfigView(viewsets.ViewSet):
    authentication_classes = [ApiAuthentication]

    def list(self, request):
        success, owner = get_owner(request)

        if not success:
            return response_message(owner)

        service_list = Service.objects.filter(owner=owner)
        service_dict_list = []

        for service_temp in service_list:
            service_dict_list.append({
                'name': service_temp.name,
                'url': service_temp.url,
                'enabled': service_temp.enabled,
                'ssl_properties': json.loads(service_temp.ssl_properties),
                'is_free': service_temp.is_free,
                'uuid': service_temp.uuid
            })

        message_dict = {
            'message': '',
            'service_dict_list': service_dict_list,
            'status_code': 200,
            'service_count': service_list.count(),
        }

        return response_message(message_dict)

    def create(self, request):
        serializer = ServiceSerializer(data=request.data)
        success, owner = get_owner(request)

        if not success:
            return response_message(owner)

        if serializer.is_valid():
            validated_data: dict = serializer.validated_data

            sys_user: SysUser = owner.sysuser_set.first()
            extra_info: dict = json.loads(sys_user.extra_info)
            free_service_count = Service.objects.filter(owner=owner, is_free=True).count()

            if extra_info.get('free_plan') and free_service_count >= extra_info.get('free_services'):
                message_dict = {
                    'message': f'Your plan allows only {extra_info.get("free_services")} free service.',
                    'status_code': 400
                }

                return response_message(message_dict)

            success, cert_dict = certificate_info(validated_data.get('url'))

            if success:
                ssl_properties = json.dumps(cert_dict)
                service_dict = {
                    'name': validated_data.get('name'),
                    'url': validated_data.get('url'),
                    'owner': owner,
                    'ssl_properties': ssl_properties,
                    'is_free': True if free_service_count <= 0 else False
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
            return get_error_dict(serializer, status_code=400)

    def delete(self, request):
        success, owner = get_owner(request)

        if not success:
            return response_message(owner)

        Service.objects.filter(uuid=request.headers.get('Service-uuid'), owner=owner).delete()

        message_dict = {
            'message': 'Service deleted successfully',
            'status_code': 200
        }

        return response_message(message_dict)
