# Generated by Django 4.0.6 on 2022-08-17 19:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api_v1', '0003_sysuser_is_free'),
    ]

    operations = [
        migrations.AlterField(
            model_name='service',
            name='name',
            field=models.CharField(max_length=30),
        ),
    ]
