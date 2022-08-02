from django.urls import path, include
from rest_framework import routers

from . import views

router = routers.DefaultRouter()

router.register(r'user/config', views.UserConfigView, basename='user_config')
router.register(r'service/config', views.ServiceConfigView, basename='user_config')

urlpatterns = [
    path('', include(router.urls))
]
