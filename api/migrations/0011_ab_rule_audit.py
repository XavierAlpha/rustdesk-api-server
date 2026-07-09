from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
from django.utils import timezone


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0010_ab_rules_and_share_guid'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AddressBookRuleAudit',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action', models.CharField(max_length=32)),
                ('target_type', models.CharField(max_length=16)),
                ('target_name', models.CharField(blank=True, default='', max_length=120)),
                ('rule', models.IntegerField(default=1, verbose_name='共享权限')),
                ('details', models.TextField(blank=True, default='')),
                ('created_at', models.DateTimeField(default=timezone.now, verbose_name='创建时间')),
                ('actor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='address_book_rule_audits', to=settings.AUTH_USER_MODEL)),
                ('profile', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='rule_audits', to='api.addressbookprofile')),
            ],
            options={
                'ordering': ('-created_at',),
                'verbose_name': '地址簿规则审计',
                'verbose_name_plural': '地址簿规则审计列表',
            },
        ),
    ]
