
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('ssl_admin/', admin.site.urls),
    path('api/v1/', include('api_v1.urls'))
]
