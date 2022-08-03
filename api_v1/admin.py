from django.contrib import admin
from . import models

# Register your models here.


class ServiceAdmin(admin.ModelAdmin):
    list_display = ['name', 'owner', 'last_seen', 'is_free', 'created', 'uuid']
    search_fields = ['name', 'last_seen', 'is_free', 'created', 'uuid']


admin.site.register(models.Owner)
admin.site.register(models.SysUser)
admin.site.register(models.Service, ServiceAdmin)
