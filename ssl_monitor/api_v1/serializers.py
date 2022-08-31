from django.contrib.auth.models import User
from rest_framework import serializers

from api_v1.models import Service, SysUser


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'


class ServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        exclude = ['owner']


class SysUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = SysUser
        exclude = ['user']
