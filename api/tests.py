import hashlib
import json
from pathlib import Path
import tempfile

from django.test import TestCase, override_settings
from nacl.signing import SigningKey

from api.models import (
    AuditSession,
    ConnLog,
    DeviceGroup,
    LoginAttempt,
    OidcPendingAuth,
    RustDesDevice,
    RustDeskPeer,
    RustDeskToken,
    StrategyProfile,
    UserProfile,
)


class ApiTestMixin:
    def setUp(self):
        self.admin = UserProfile.objects.create_user(
            username="admin",
            password="admin-pass",
            is_admin=True,
            is_superuser=True,
        )
        self.user = UserProfile.objects.create_user(
            username="alice",
            password="alice-pass",
            email="alice@example.test",
        )

    def _post_json(self, path, payload, token=None):
        headers = self._auth_headers(token)
        return self.client.post(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )

    def _put_json(self, path, payload, token=None):
        headers = self._auth_headers(token)
        return self.client.put(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )

    def _delete_json(self, path, payload=None, token=None):
        headers = self._auth_headers(token)
        return self.client.delete(
            path,
            data=json.dumps(payload if payload is not None else {}),
            content_type="application/json",
            **headers,
        )

    @staticmethod
    def _auth_headers(token):
        return {"HTTP_AUTHORIZATION": f"Bearer {token}"} if token else {}

    def _login(self, username, password, rid="123456789", uuid="device-uuid"):
        response = self._post_json(
            "/api/login",
            {
                "username": username,
                "password": password,
                "id": rid,
                "uuid": uuid,
                "type": "client",
                "deviceInfo": {"platform": "linux"},
            },
        )
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertIn("access_token", body)
        return body["access_token"]

    def _device(self, owner=None, rid="123456789", uuid="device-uuid", **overrides):
        data = {
            "rid": rid,
            "cpu": "-",
            "hostname": "desktop",
            "memory": "-",
            "os": "linux",
            "uuid": uuid,
            "username": "desktop-user",
            "version": "2.0.0",
            "owner": owner,
            "owner_name": owner.username if owner else "",
        }
        data.update(overrides)
        return RustDesDevice.objects.create(**data)


class ApiContractTests(ApiTestMixin, TestCase):
    def test_login_requires_bearer_token_for_current_user(self):
        token = self._login("alice", "alice-pass")

        query_token_response = self._post_json("/api/currentUser", {"access_token": token})
        self.assertEqual(query_token_response.status_code, 401)

        response = self._post_json("/api/currentUser", {}, token=token)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["name"], "alice")

    def test_failed_login_returns_401_with_error_body(self):
        response = self._post_json(
            "/api/login",
            {"username": "alice", "password": "wrong", "id": "123456789", "uuid": "device-uuid"},
        )
        self.assertEqual(response.status_code, 401)
        self.assertIn("error", response.json())
        self.assertEqual(LoginAttempt.objects.filter(ip="127.0.0.1").count(), 1)

    def test_repeated_login_failures_lock_out_ip(self):
        for _ in range(10):
            self._post_json(
                "/api/login",
                {"username": "alice", "password": "wrong", "id": "123456789", "uuid": "device-uuid"},
            )
        locked = self._post_json(
            "/api/login",
            {"username": "alice", "password": "alice-pass", "id": "123456789", "uuid": "device-uuid"},
        )
        self.assertEqual(locked.status_code, 429)
        self.assertIn("error", locked.json())

    def test_successful_login_clears_failures_and_stores_hashed_token(self):
        self._post_json(
            "/api/login",
            {"username": "alice", "password": "wrong", "id": "123456789", "uuid": "device-uuid"},
        )
        token = self._login("alice", "alice-pass")
        self.assertEqual(LoginAttempt.objects.count(), 0)

        stored = RustDeskToken.objects.get(uid=str(self.user.id))
        self.assertNotEqual(stored.access_token, token)
        self.assertEqual(stored.access_token, hashlib.sha256(token.encode()).hexdigest())

        # currentUser echoes the presented raw token, never the stored hash.
        response = self._post_json("/api/currentUser", {}, token=token)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["access_token"], token)

    def test_relogin_rotates_the_stored_token(self):
        first = self._login("alice", "alice-pass")
        second = self._login("alice", "alice-pass")
        self.assertNotEqual(first, second)

        stale = self._post_json("/api/currentUser", {}, token=first)
        self.assertEqual(stale.status_code, 401)
        fresh = self._post_json("/api/currentUser", {}, token=second)
        self.assertEqual(fresh.status_code, 200, fresh.content)

    def test_oidc_auth_query_reads_state_from_database(self):
        # Simulates the callback having completed on a different worker: the
        # pending state lives in the DB, not in process memory.
        OidcPendingAuth.objects.create(
            state="test-state",
            provider="example",
            status=OidcPendingAuth.STATUS_DONE,
            body={"access_token": "raw-token", "type": "access_token"},
        )
        response = self.client.get("/api/oidc/auth-query?code=test-state")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["access_token"], "raw-token")
        self.assertFalse(OidcPendingAuth.objects.filter(state="test-state").exists())

    def test_telemetry_requires_the_token_bound_to_that_device(self):
        response = self._post_json(
            "/api/heartbeat",
            {"id": "x" * 200, "uuid": "device-uuid"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(RustDesDevice.objects.exists())

        token = self._login("alice", "alice-pass")
        unauthenticated = self._post_json(
            "/api/sysinfo",
            {"id": "123456789", "uuid": "device-uuid", "hostname": "desktop"},
        )
        self.assertEqual(unauthenticated.status_code, 401)
        wrong_device = self._post_json(
            "/api/sysinfo",
            {"id": "987654321", "uuid": "other-device", "hostname": "desktop"},
            token=token,
        )
        self.assertEqual(wrong_device.status_code, 401)

        sysinfo = self._post_json(
            "/api/sysinfo",
            {"id": "123456789", "uuid": "device-uuid", "hostname": "desktop"},
            token=token,
        )
        self.assertEqual(sysinfo.status_code, 200, sysinfo.content)
        self.assertTrue(RustDesDevice.objects.filter(rid="123456789").exists())
        heartbeat = self._post_json(
            "/api/heartbeat",
            {"id": "123456789", "uuid": "device-uuid"},
            token=token,
        )
        self.assertEqual(heartbeat.status_code, 200, heartbeat.content)

    def test_address_book_peers_match_flutter_client_contract(self):
        token = self._login("alice", "alice-pass")
        RustDeskPeer.objects.create(
            uid=str(self.user.id),
            rid="765432100",
            username="mira",
            hostname="studio-mac",
            platform="Mac OS",
            alias="Design workstation",
            tags="studio,trusted",
            note="Primary workstation",
            device_group_name="Design",
            login_name="mira@example.test",
            same_server=True,
            rhash="personal-hash",
            profile_guid=f"personal-{self.user.id}",
        )

        response = self.client.post(
            "/api/ab/peers?current=1&pageSize=100",
            data="",
            content_type="application/json",
            **self._auth_headers(token),
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["total"], 1)
        self.assertEqual(
            response.json()["data"][0],
            {
                "id": "765432100",
                "username": "mira",
                "hostname": "studio-mac",
                "platform": "Mac OS",
                "alias": "Design workstation",
                "tags": ["studio", "trusted"],
                "note": "Primary workstation",
                "device_group_name": "Design",
                "loginName": "mira@example.test",
                "same_server": True,
                "hash": "personal-hash",
                "password": "",
            },
        )

    def test_admin_can_manage_users_and_disabled_users_cannot_login(self):
        admin_token = self._login("admin", "admin-pass", rid="900000001", uuid="admin-device")

        created = self._post_json(
            "/api/users",
            {"name": "bob", "password": "bob-pass", "email": "bob@example.test", "group_name": "ops"},
            token=admin_token,
        )
        self.assertEqual(created.status_code, 200, created.content)
        user_guid = created.json()["guid"]

        duplicate = self._post_json(
            "/api/users",
            {"name": "bob", "password": "bob-pass"},
            token=admin_token,
        )
        self.assertEqual(duplicate.status_code, 409)

        listed = self.client.get("/api/users?name=bob", **self._auth_headers(admin_token))
        self.assertEqual(listed.status_code, 200, listed.content)
        self.assertEqual(listed.json()["total"], 1)
        self.assertEqual(listed.json()["data"][0]["group_name"], "ops")

        disabled = self._post_json(f"/api/users/{user_guid}/disable", {}, token=admin_token)
        self.assertEqual(disabled.status_code, 200, disabled.content)
        denied = self._post_json(
            "/api/login",
            {"username": "bob", "password": "bob-pass", "id": "800000001", "uuid": "bob-device"},
        )
        # Inactive and unknown accounts deliberately share the same response so
        # the login endpoint does not become an account-status oracle.
        self.assertEqual(denied.status_code, 401)

        enabled = self._post_json(f"/api/users/{user_guid}/enable", {}, token=admin_token)
        self.assertEqual(enabled.status_code, 200, enabled.content)
        self.assertTrue(enabled.json()["status"])

    def test_device_groups_and_strategies_drive_heartbeat_contract(self):
        admin_token = self._login("admin", "admin-pass", rid="900000001", uuid="admin-device")
        self._device(owner=self.user)
        device_token = self._login("alice", "alice-pass")

        created_group = self._post_json(
            "/api/device-groups",
            {
                "name": "ops",
                "note": "Operations devices",
                "allowed_incomings": ["admin"],
            },
            token=admin_token,
        )
        self.assertEqual(created_group.status_code, 200, created_group.content)
        group_guid = created_group.json()["guid"]

        assigned_devices = self._post_json(
            f"/api/device-groups/{group_guid}",
            ["123456789"],
            token=admin_token,
        )
        self.assertEqual(assigned_devices.status_code, 200, assigned_devices.content)
        self.assertEqual(assigned_devices.json()["updated"], 1)

        strategy = StrategyProfile.objects.create(
            name="high-quality",
            config_options=json.dumps({"quality": "best", "enable-audio": True}),
        )
        assigned_strategy = self._post_json(
            "/api/strategies/assign",
            {"strategy": str(strategy.guid), "groups": [group_guid]},
            token=admin_token,
        )
        self.assertEqual(assigned_strategy.status_code, 200, assigned_strategy.content)
        self.assertEqual(assigned_strategy.json()["groups"], 1)

        heartbeat = self._post_json(
            "/api/heartbeat",
            {"id": "123456789", "uuid": "device-uuid", "modified_at": 0},
            token=device_token,
        )
        self.assertEqual(heartbeat.status_code, 200, heartbeat.content)
        self.assertEqual(heartbeat.json()["strategy"]["config_options"]["quality"], "best")

        disabled = self._put_json(
            f"/api/strategies/{strategy.guid}/status",
            {"enabled": False},
            token=admin_token,
        )
        self.assertEqual(disabled.status_code, 200, disabled.content)
        self.assertFalse(disabled.json()["enabled"])

        heartbeat = self._post_json(
            "/api/heartbeat",
            {"id": "123456789", "uuid": "device-uuid", "modified_at": 0},
            token=device_token,
        )
        self.assertEqual(heartbeat.status_code, 200, heartbeat.content)
        self.assertNotIn("strategy", heartbeat.json())

    def test_disabled_devices_are_blocked_by_login_and_heartbeat(self):
        device = self._device(owner=self.user)
        token = self._login("alice", "alice-pass")
        device.is_active = False
        device.save(update_fields=["is_active"])

        login = self._post_json(
            "/api/login",
            {
                "username": "alice",
                "password": "alice-pass",
                "id": "123456789",
                "uuid": "device-uuid",
            },
        )
        self.assertEqual(login.status_code, 403)

        heartbeat = self._post_json(
            "/api/heartbeat",
            {"id": "123456789", "uuid": "device-uuid"},
            token=token,
        )
        self.assertEqual(heartbeat.status_code, 403)

    def test_plugin_sign_requires_configured_signing_key(self):
        admin_token = self._login("admin", "admin-pass", rid="900000001", uuid="admin-device")
        response = self._post_json(
            "/lic/web/api/plugin-sign",
            {"msg": [1, 2, 3], "plugin_id": "sample", "version": "1.0.0"},
            token=admin_token,
        )
        self.assertEqual(response.status_code, 503)

    @override_settings(ALLOW_REGISTRATION=True)
    def test_first_public_registration_never_bootstraps_an_administrator(self):
        UserProfile.objects.all().delete()
        response = self.client.post(
            "/api/user_action?action=register",
            {"user": "first-user", "pwd": "strong-pass"},
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["code"], 1)
        user = UserProfile.objects.get(username="first-user")
        self.assertFalse(user.is_admin)
        self.assertFalse(user.is_superuser)

    @override_settings(PLUGIN_SIGNING_KEY=SigningKey.generate().encode().hex())
    def test_plugin_sign_is_an_admin_only_operation(self):
        user_token = self._login("alice", "alice-pass")
        admin_token = self._login("admin", "admin-pass", rid="900000001", uuid="admin-device")
        payload = {"msg": [1, 2, 3], "plugin_id": "sample", "version": "1.0.0"}

        self.assertEqual(self._post_json("/lic/web/api/plugin-sign", payload).status_code, 401)
        self.assertEqual(
            self._post_json("/lic/web/api/plugin-sign", payload, token=user_token).status_code,
            403,
        )
        signed = self._post_json("/lic/web/api/plugin-sign", payload, token=admin_token)
        self.assertEqual(signed.status_code, 200, signed.content)
        self.assertEqual(len(signed.json()["signed_msg"]), 67)

    def test_device_group_delete_detaches_devices(self):
        admin_token = self._login("admin", "admin-pass", rid="900000001", uuid="admin-device")
        device = self._device(owner=self.user, device_group_name="ops")
        group = DeviceGroup.objects.create(name="ops")

        response = self._delete_json(f"/api/device-groups/{group.guid}", token=admin_token)
        self.assertEqual(response.status_code, 200, response.content)
        device.refresh_from_db()
        self.assertEqual(device.device_group_name, "")

    @override_settings(
        STORAGES={
            "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
            "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
        }
    )
    def test_front_device_page_uses_modern_device_owner_relation(self):
        self._device(owner=self.user, rid="765432100", uuid="owned-device")
        self.client.force_login(self.user)

        response = self.client.get("/api/work")

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.context["page_obj"].paginator.count, 1)
        self.assertContains(response, "765432100")

    @override_settings(
        STORAGES={
            "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
            "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
        }
    )
    def test_front_device_pages_merge_legacy_metadata_and_expose_unknown_state(self):
        self._device(owner=self.user, rid="765432100", uuid="owned-device")
        RustDeskPeer.objects.create(
            uid=str(self.user.id),
            rid="765432100",
            username="desktop-user",
            hostname="desktop",
            alias="Primary desktop",
            platform="Linux",
            tags="work",
            rhash="secret-hash",
        )
        RustDeskPeer.objects.create(
            uid=str(self.user.id),
            rid="765432101",
            username="address-book-user",
            hostname="unknown",
            alias="Address book only",
            platform="Android",
            tags="mobile",
            rhash="",
        )
        self.client.force_login(self.user)

        work_response = self.client.get("/api/work")
        home_response = self.client.get("/api/home")

        self.assertEqual(work_response.status_code, 200, work_response.content)
        items = {item["rid"]: item for item in work_response.context["page_obj"]}
        self.assertEqual(set(items), {"765432100", "765432101"})
        self.assertEqual(items["765432100"]["alias"], "Primary desktop")
        self.assertEqual(items["765432100"]["platform"], "Linux")
        self.assertEqual(items["765432101"]["status"], "未知状态")
        self.assertEqual(home_response.context["summary"], {"total": 2, "online": 1, "offline": 0, "unknown": 1})


class SessionIntegrityTests(ApiTestMixin, TestCase):
    """Regressions for defects that let a session outlive its owner's intent."""

    def test_logout_revokes_the_device_that_asked(self):
        desktop = self._login("alice", "alice-pass", rid="111111111", uuid="desktop")
        phone = self._login("alice", "alice-pass", rid="222222222", uuid="phone")
        self.assertEqual(RustDeskToken.objects.filter(uid=str(self.user.id)).count(), 2)

        logout = self._post_json("/api/logout", {"id": "111111111", "uuid": "desktop"}, token=desktop)
        self.assertEqual(logout.status_code, 200, logout.content)

        # The desktop is signed out ...
        self.assertEqual(self._post_json("/api/currentUser", {}, token=desktop).status_code, 401)
        # ... and the phone, which never asked, is still signed in.
        self.assertEqual(self._post_json("/api/currentUser", {}, token=phone).status_code, 200)

    def test_logout_cannot_revoke_a_device_by_public_identifiers(self):
        token = self._login("alice", "alice-pass", rid="111111111", uuid="desktop")
        denied = self._post_json("/api/logout", {"id": "111111111", "uuid": "desktop"})
        self.assertEqual(denied.status_code, 401)
        self.assertEqual(self._post_json("/api/currentUser", {}, token=token).status_code, 200)

    def test_one_token_row_per_device(self):
        first = self._login("alice", "alice-pass", rid="111111111", uuid="desktop")
        second = self._login("alice", "alice-pass", rid="111111111", uuid="desktop")

        # Re-login rotates in place instead of leaving an unrevokable second row.
        self.assertEqual(
            RustDeskToken.objects.filter(uid=str(self.user.id), rid="111111111", uuid="desktop").count(),
            1,
        )
        self.assertEqual(self._post_json("/api/currentUser", {}, token=first).status_code, 401)
        self.assertEqual(self._post_json("/api/currentUser", {}, token=second).status_code, 200)

    def test_auth_body_carries_the_info_the_desktop_client_requires(self):
        response = self._post_json(
            "/api/login",
            {"username": "alice", "password": "alice-pass", "id": "123456789", "uuid": "device-uuid"},
        )
        user = response.json()["user"]
        # UserPayload has no default for `info`; omitting it makes the whole body
        # fail to deserialise and silently discards a successful OIDC login.
        self.assertIn("info", user)
        self.assertIn("login_device_whitelist", user["info"])

    @override_settings(TRUST_PROXY_HEADERS=False)
    def test_forwarded_headers_cannot_choose_the_rate_limit_bucket(self):
        # Every attempt claims a different forwarded address; with the header
        # untrusted they all land in the same bucket and still trip the lockout.
        for spoofed in range(10):
            self.client.post(
                "/api/login",
                data=json.dumps({"username": "alice", "password": "wrong", "id": "1", "uuid": "u"}),
                content_type="application/json",
                HTTP_X_FORWARDED_FOR=f"198.51.100.{spoofed}",
            )
        locked = self.client.post(
            "/api/login",
            data=json.dumps({"username": "alice", "password": "alice-pass", "id": "1", "uuid": "u"}),
            content_type="application/json",
            HTTP_X_FORWARDED_FOR="203.0.113.9",
        )
        self.assertEqual(locked.status_code, 429)

    def test_out_of_range_pagination_is_clamped(self):
        token = self._login("alice", "alice-pass")
        for query in ("current=0", "current=-5", "pageSize=-1", "current=0&pageSize=0"):
            response = self.client.post(
                f"/api/ab/peers?{query}",
                content_type="application/json",
                **self._auth_headers(token),
            )
            self.assertEqual(response.status_code, 200, f"{query}: {response.content}")


class SensitiveIngestionTests(ApiTestMixin, TestCase):
    def _raw_record(self, query, body, token=None):
        return self.client.post(
            f"/api/record?{query}",
            data=body,
            content_type="application/octet-stream",
            **self._auth_headers(token),
        )

    def test_record_upload_is_authenticated_sequential_and_device_isolated(self):
        self._device(owner=self.user)
        token = self._login("alice", "alice-pass")
        with tempfile.TemporaryDirectory() as upload_root:
            with self.settings(
                RECORD_UPLOAD_ROOT=Path(upload_root),
                RECORD_UPLOAD_MAX_CHUNK_BYTES=1024,
                RECORD_UPLOAD_MAX_FILE_BYTES=2048,
                DATA_UPLOAD_MAX_MEMORY_SIZE=1024,
            ):
                self.assertEqual(
                    self._raw_record("type=new&file=session.webm", b"").status_code,
                    401,
                )
                created = self._raw_record("type=new&file=session.webm", b"", token)
                self.assertEqual(created.status_code, 200, created.content)
                traversal = self._raw_record("type=new&file=../session.webm", b"", token)
                self.assertEqual(traversal.status_code, 400)

                first = self._raw_record(
                    "type=part&file=session.webm&offset=0&length=4",
                    b"data",
                    token,
                )
                self.assertEqual(first.status_code, 200, first.content)
                conflict = self._raw_record(
                    "type=part&file=session.webm&offset=0&length=4",
                    b"evil",
                    token,
                )
                self.assertEqual(conflict.status_code, 409)

                files = list(Path(upload_root).glob("*/session.webm"))
                self.assertEqual(len(files), 1)
                self.assertEqual(files[0].read_bytes(), b"data")

    def test_audit_ingestion_and_notes_are_scoped_to_authenticated_participants(self):
        self._device(owner=self.user, rid="111111111", uuid="host-device")
        host_token = self._login("alice", "alice-pass", rid="111111111", uuid="host-device")
        controller = UserProfile.objects.create_user(
            username="bob",
            password="bob-pass",
            rid="",
            uuid="",
            rtype="",
            deviceInfo="",
        )
        self._device(owner=controller, rid="222222222", uuid="controller-device")
        controller_token = self._login(
            "bob",
            "bob-pass",
            rid="222222222",
            uuid="controller-device",
        )
        outsider = UserProfile.objects.create_user(
            username="mallory",
            password="mallory-pass",
            rid="",
            uuid="",
            rtype="",
            deviceInfo="",
        )
        self._device(owner=outsider, rid="333333333", uuid="outsider-device")
        outsider_token = self._login(
            "mallory",
            "mallory-pass",
            rid="333333333",
            uuid="outsider-device",
        )
        new_event = {
            "action": "new",
            "id": "111111111",
            "uuid": "host-device",
            "conn_id": 7,
            "session_id": 99,
            "ip": "192.0.2.10",
            "type": 0,
        }

        self.assertEqual(self._post_json("/api/audit/conn", new_event).status_code, 401)
        created = self._post_json("/api/audit/conn", new_event, token=host_token)
        self.assertEqual(created.status_code, 200, created.content)
        updated = self._post_json(
            "/api/audit/conn",
            {
                "id": "111111111",
                "uuid": "host-device",
                "conn_id": 7,
                "session_id": 99,
                "peer": ["222222222", "bob"],
                "type": 0,
            },
            token=host_token,
        )
        self.assertEqual(updated.status_code, 200, updated.content)
        self.assertEqual(ConnLog.objects.get().from_id, "222222222")

        active = self.client.get(
            "/api/audit/conn/active?id=111111111&session_id=99&conn_type=0",
            **self._auth_headers(controller_token),
        )
        self.assertEqual(active.status_code, 200, active.content)
        guid = active.json()
        self.assertTrue(guid)
        session = AuditSession.objects.get(guid=guid)
        self.assertEqual(session.actor_id, controller.id)

        direct_note = self._post_json(
            "/api/audit/conn",
            {"id": "111111111", "session_id": 99, "note": "during session"},
            token=controller_token,
        )
        self.assertEqual(direct_note.status_code, 200, direct_note.content)
        denied = self._put_json(
            "/api/audit",
            {"guid": guid, "note": "tampered"},
            token=outsider_token,
        )
        self.assertEqual(denied.status_code, 404)
        allowed = self._put_json(
            "/api/audit",
            {"guid": guid, "note": "approved"},
            token=controller_token,
        )
        self.assertEqual(allowed.status_code, 200, allowed.content)
        session.refresh_from_db()
        self.assertEqual(session.note, "approved")
