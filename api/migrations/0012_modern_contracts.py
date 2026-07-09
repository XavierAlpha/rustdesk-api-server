import uuid

from django.db import migrations, models
import django.utils.timezone


def populate_strategy_guids(apps, schema_editor):
    strategy_model = apps.get_model("api", "StrategyProfile")
    for strategy in strategy_model.objects.filter(guid__isnull=True):
        strategy.guid = str(uuid.uuid4())
        strategy.save(update_fields=["guid"])


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0011_ab_rule_audit"),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="group_name",
            field=models.CharField(blank=True, default="", max_length=120, verbose_name="用户组"),
        ),
        migrations.AlterField(
            model_name="rustdesktoken",
            name="access_token",
            field=models.CharField(blank=True, db_index=True, max_length=128, verbose_name="access_token"),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="strategy_name",
            field=models.CharField(blank=True, default="", max_length=60, verbose_name="策略名称"),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="login_verification_disabled",
            field=models.BooleanField(default=False, verbose_name="禁用登录验证"),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="tfa_enforced",
            field=models.BooleanField(default=False, verbose_name="强制双因素认证"),
        ),
        migrations.AddField(
            model_name="rustdesdevice",
            name="is_active",
            field=models.BooleanField(default=True, verbose_name="是否启用"),
        ),
        migrations.AlterField(
            model_name="connlog",
            name="id",
            field=models.AutoField(primary_key=True, serialize=False, verbose_name="ID"),
        ),
        migrations.AlterField(
            model_name="filelog",
            name="id",
            field=models.AutoField(primary_key=True, serialize=False, verbose_name="ID"),
        ),
        migrations.AddField(
            model_name="strategyprofile",
            name="enabled",
            field=models.BooleanField(default=True, verbose_name="是否启用"),
        ),
        migrations.AddField(
            model_name="strategyprofile",
            name="guid",
            field=models.CharField(blank=True, editable=False, max_length=64, null=True),
        ),
        migrations.RunPython(populate_strategy_guids, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="strategyprofile",
            name="guid",
            field=models.CharField(default=uuid.uuid4, editable=False, max_length=64, unique=True),
        ),
        migrations.CreateModel(
            name="DeviceGroup",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("guid", models.CharField(default=uuid.uuid4, editable=False, max_length=64, unique=True)),
                ("name", models.CharField(max_length=120, unique=True, verbose_name="设备组名称")),
                ("note", models.TextField(blank=True, default="", verbose_name="备注")),
                ("allowed_incomings", models.TextField(blank=True, default="", verbose_name="允许来源")),
                ("strategy_name", models.CharField(blank=True, default="", max_length=60, verbose_name="策略名称")),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now, verbose_name="创建时间")),
                ("updated_at", models.DateTimeField(auto_now=True, verbose_name="更新时间")),
            ],
            options={
                "verbose_name": "设备组",
                "verbose_name_plural": "设备组列表",
                "ordering": ("name",),
            },
        ),
    ]
