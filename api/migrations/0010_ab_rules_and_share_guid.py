from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
from django.utils import timezone
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0009_refactor_api_models'),
        ('auth', '0012_alter_user_first_name_max_length'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='addressbookshare',
            name='guid',
            field=models.CharField(default=uuid.uuid4, editable=False, max_length=64, unique=True),
        ),
        migrations.CreateModel(
            name='AddressBookRule',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('guid', models.CharField(default=uuid.uuid4, editable=False, max_length=64, unique=True)),
                ('rule', models.IntegerField(default=1, verbose_name='共享权限')),
                ('is_everyone', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(default=timezone.now, verbose_name='创建时间')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='更新时间')),
                ('group', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='address_book_rules', to='auth.group')),
                ('profile', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='rules', to='api.addressbookprofile')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='address_book_rules', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': '地址簿规则',
                'verbose_name_plural': '地址簿规则列表',
            },
        ),
    ]
