from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


def merge_duplicate_sessions(apps, schema_editor):
    audit_session = apps.get_model("api", "AuditSession")
    duplicates = (
        audit_session.objects.values("peer_id", "session_id")
        .annotate(count=models.Count("id"))
        .filter(count__gt=1)
    )
    for duplicate in duplicates.iterator():
        sessions = audit_session.objects.filter(
            peer_id=duplicate["peer_id"],
            session_id=duplicate["session_id"],
        ).order_by("-updated_at", "-id")
        canonical = sessions.first()
        if canonical is not None:
            sessions.exclude(pk=canonical.pk).delete()


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("api", "0015_rustdesktoken_unique_token_per_device"),
    ]

    operations = [
        migrations.AddField(
            model_name="auditsession",
            name="actor",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="audit_sessions",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.RunPython(merge_duplicate_sessions, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="auditsession",
            constraint=models.UniqueConstraint(
                fields=("peer_id", "session_id"),
                name="unique_audit_session_per_connection",
            ),
        ),
    ]
