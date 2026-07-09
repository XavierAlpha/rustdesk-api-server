import json

from django.test import TestCase, override_settings

from api.models import DeviceGroup, RustDesDevice, RustDeskPeer, StrategyProfile, UserProfile


class ApiContractTests(TestCase):
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

    def test_login_requires_bearer_token_for_current_user(self):
        token = self._login("alice", "alice-pass")

        query_token_response = self._post_json("/api/currentUser", {"access_token": token})
        self.assertEqual(query_token_response.status_code, 401)

        response = self._post_json("/api/currentUser", {}, token=token)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["name"], "alice")

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
        self.assertEqual(denied.status_code, 403)

        enabled = self._post_json(f"/api/users/{user_guid}/enable", {}, token=admin_token)
        self.assertEqual(enabled.status_code, 200, enabled.content)
        self.assertTrue(enabled.json()["status"])

    def test_device_groups_and_strategies_drive_heartbeat_contract(self):
        admin_token = self._login("admin", "admin-pass", rid="900000001", uuid="admin-device")
        self._device(owner=self.user)

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
        )
        self.assertEqual(heartbeat.status_code, 200, heartbeat.content)
        self.assertNotIn("strategy", heartbeat.json())

    def test_disabled_devices_are_blocked_by_login_and_heartbeat(self):
        self._device(owner=self.user, is_active=False)

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
        )
        self.assertEqual(heartbeat.status_code, 403)

    def test_plugin_sign_requires_configured_signing_key(self):
        response = self._post_json(
            "/lic/web/api/plugin-sign",
            {"msg": [1, 2, 3], "plugin_id": "sample", "version": "1.0.0"},
        )
        self.assertEqual(response.status_code, 503)

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
