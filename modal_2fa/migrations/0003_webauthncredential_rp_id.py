# Generated by Django 3.2.7 on 2024-01-31 08:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('modal_2fa', '0002_failedloginattempt_webauthncredential'),
    ]

    operations = [
        migrations.AddField(
            model_name='webauthncredential',
            name='rp_id',
            field=models.CharField(default='localhost', max_length=80),
            preserve_default=False,
        ),
    ]
