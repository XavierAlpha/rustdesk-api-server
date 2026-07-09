# cython:language_level=3
from django.http import JsonResponse, HttpResponse, HttpResponseRedirect
import base64
import binascii
import json
import datetime
import logging
import math
import os
import secrets
import uuid
from django.contrib import auth
# from django.forms.models import model_to_dict
from api.models import (
    RustDeskToken,
    UserProfile,
    RustDeskTag,
    RustDeskPeer,
    RustDesDevice,
    ConnLog,
    FileLog,
    StrategyProfile,
    DeviceGroup,
    AddressBookProfile,
    AddressBookShare,
    AddressBookRule,
    AddressBookRuleAudit,
    AuditSession,
    AlarmLog,
)
from django.contrib.auth.models import Group
from django.db import transaction
from django.db import IntegrityError
from django.db.models import Q, QuerySet
from django.utils import timezone
from .views_front import *
from django.utils.translation import gettext as _
from django.conf import settings
from authlib.integrations.requests_client import OAuth2Session
from nacl.signing import SigningKey

logger = logging.getLogger(__name__)
EFFECTIVE_SECONDS = 7200
MAX_DEPLOY_KEY_LEN = 512
MAX_PLUGIN_SIGN_MSG_BYTES = 64 * 1024
OIDC_PENDING = {}


def _load_json(request):
    try:
        if request.body:
            return json.loads(request.body.decode())
    except Exception:
        return {}
    return {}


def _get_bearer_token(request):
    auth = request.META.get('HTTP_AUTHORIZATION', '')
    if auth.startswith('Bearer '):
        return auth.split('Bearer ')[-1].strip()
    return ''


def _get_token_user(request):
    token_str = _get_bearer_token(request)
    if not token_str:
        return None, None
    token = RustDeskToken.objects.filter(Q(access_token=token_str)).first()
    if not token:
        return None, None
    if _token_expired(token):
        token.delete()
        return None, None
    user = UserProfile.objects.filter(Q(id=token.uid)).first()
    if user and not user.is_active:
        return token, None
    return token, user


def _token_expired(token):
    now = timezone.now()
    expires_at = token.expires_at
    if not expires_at and token.create_time:
        expires_at = token.create_time + datetime.timedelta(seconds=EFFECTIVE_SECONDS)
    if expires_at and expires_at < now:
        return True
    return False


def _issue_access_token(user):
    expires_at = timezone.now() + datetime.timedelta(seconds=EFFECTIVE_SECONDS)
    token = RustDeskToken.objects.filter(Q(uid=str(user.id)) & Q(username=user.username) & Q(rid=user.rid)).first()
    if token and _token_expired(token):
        token.delete()
        token = None
    if not token:
        token = RustDeskToken(
            username=user.username,
            uid=str(user.id),
            uuid=user.uuid,
            rid=user.rid,
            access_token=secrets.token_urlsafe(32),
        )
    token.expires_at = expires_at
    token.save()
    return token


def _auth_body(user, token):
    return {
        'access_token': token.access_token,
        'type': 'access_token',
        'user': {
            'name': user.username,
            'display_name': user.username,
            'avatar': '',
            'status': 1 if user.is_active else 0,
            'is_admin': True if user.is_admin else False,
            'email': user.email or '',
            'note': user.note or '',
        },
    }


def _oidc_provider_name(op):
    name = str(op or '').strip()
    if name.startswith('common-oidc/'):
        try:
            payload = json.loads(name[len('common-oidc/'):])
            name = payload.get('name') or payload.get('op') or ''
        except Exception:
            name = ''
    if name.startswith('oidc/'):
        name = name[len('oidc/'):]
    return name

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def _log_event(request, event, level="info", **extra):
    user = getattr(request, 'user', None)
    username = user.username if user and getattr(user, 'is_authenticated', False) else extra.pop('username', 'anonymous')
    payload = {
        'event': event,
        'user': username,
        'ip': get_client_ip(request),
        'path': getattr(request, 'path', ''),
        'method': getattr(request, 'method', ''),
    }
    payload.update({k: v for k, v in extra.items() if v is not None})
    details = json.dumps(payload, ensure_ascii=False)
    log_fn = getattr(logger, level, logger.info)
    log_fn("event=%s details=%s", event, details)


def _record_dir():
    base_dir = getattr(settings, "BASE_DIR", None)
    if base_dir is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.fspath(base_dir), "records")


def _safe_record_name(name):
    name = os.path.basename(name or "").strip()
    if not name:
        return ""
    return name[:255]


def _plugin_signing_key():
    raw = getattr(settings, "PLUGIN_SIGNING_KEY", "").strip()
    if not raw:
        return None
    for decoder in (
        lambda value: base64.b64decode(value, validate=True),
        lambda value: binascii.unhexlify(value),
    ):
        try:
            key = decoder(raw)
        except (binascii.Error, ValueError):
            continue
        if len(key) == 32:
            return SigningKey(key)
    return None


def _personal_guid(user):
    return f'personal-{user.id}'


def _personal_profile_name():
    lang = str(getattr(settings, "LANGUAGE_CODE", "")).lower()
    return "我的地址簿" if lang.startswith("zh") else "My address book"


def _is_reserved_ab_profile_name(name):
    return name in {"My address book", "我的地址簿"}


def _ensure_personal_profile(user):
    guid = _personal_guid(user)
    profile = AddressBookProfile.objects.filter(Q(guid=guid)).first()
    if profile:
        if str(profile.owner_id) != str(user.id):
            profile.owner = user
        if not profile.name:
            profile.name = _personal_profile_name()
        profile.rule = 3
        profile.save(update_fields=["owner", "name", "rule", "updated_at"])
        return profile
    profile = AddressBookProfile(
        guid=guid,
        name=_personal_profile_name(),
        owner=user,
        rule=3,
    )
    profile.save()
    return profile


def _is_personal_guid(guid):
    return str(guid).startswith("personal-")


def _get_rule_access(profile, user):
    rule = 0
    share = AddressBookShare.objects.filter(Q(profile=profile) & Q(user=user)).first()
    if share:
        rule = max(rule, share.rule)
    rules = AddressBookRule.objects.filter(Q(profile=profile))
    if rules.exists():
        rule = max(rule, rules.filter(Q(is_everyone=True)).values_list("rule", flat=True).first() or 0)
        if user.groups.exists():
            group_rules = rules.filter(Q(group__in=user.groups.all())).values_list("rule", flat=True)
            for r in group_rules:
                rule = max(rule, r)
        user_rule = rules.filter(Q(user=user)).values_list("rule", flat=True).first()
        if user_rule:
            rule = max(rule, user_rule)
    return rule


def _audit_ab_rule(profile, actor, action, target_type, target_name, rule, details=None):
    if not profile:
        return
    payload = ''
    if details is not None:
        try:
            payload = json.dumps(details, ensure_ascii=False)
        except Exception:
            payload = str(details)
    AddressBookRuleAudit.objects.create(
        profile=profile,
        actor=actor if actor and getattr(actor, 'id', None) else None,
        action=action,
        target_type=target_type,
        target_name=target_name or '',
        rule=int(rule or 1),
        details=payload,
    )

def _get_profile_access(user, guid):
    if guid == _personal_guid(user):
        return None, user, 3
    profile = AddressBookProfile.objects.filter(Q(guid=guid)).first()
    if not profile:
        return None, None, 0
    if user.is_admin:
        return profile, profile.owner, 3
    if str(profile.owner_id) == str(user.id):
        return profile, profile.owner, 3
    rule = _get_rule_access(profile, user)
    if not rule:
        return profile, None, 0
    return profile, profile.owner, rule


def _can_write_rule(rule):
    return rule in (2, 3)


def _safe_tags(tags):
    if not isinstance(tags, list):
        return []
    return [str(x) for x in tags if str(x).strip() != '']


def _device_update_fields(postdata):
    mapping = {
        'cpu': 'cpu',
        'hostname': 'hostname',
        'memory': 'memory',
        'os': 'os',
        'username': 'username',
        'version': 'version',
        'device_name': 'hostname',
        'device_username': 'username',
        'device_group_name': 'device_group_name',
        'note': 'note',
        'preset-device-group-name': 'device_group_name',
        'preset-note': 'note',
        'preset-strategy-name': 'strategy_name',
        'strategy_name': 'strategy_name',
        'address_book_name': 'address_book_name',
        'address_book_tag': 'address_book_tag',
        'address_book_alias': 'address_book_alias',
        'address_book_password': 'address_book_password',
        'address_book_note': 'address_book_note',
        'preset-address-book-name': 'address_book_name',
        'preset-address-book-tag': 'address_book_tag',
        'preset-address-book-alias': 'address_book_alias',
        'preset-address-book-password': 'address_book_password',
        'preset-address-book-note': 'address_book_note',
    }
    updates = {}
    for key, field in mapping.items():
        if key in postdata and postdata[key] is not None:
            updates[field] = postdata[key]
    return updates


def _valid_deploy_text(value, min_len=1, max_len=100):
    if not isinstance(value, str):
        return False
    if len(value) < min_len or len(value) > max_len:
        return False
    return not any(ch.isspace() or ord(ch) < 32 for ch in value)


def _assign_owner(device, owner_name, link_user=True, allow_override=True):
    if not owner_name:
        return
    if not allow_override and device.owner_name and device.owner_name != owner_name:
        return
    device.owner_name = owner_name
    if link_user:
        owner = UserProfile.objects.filter(Q(username=owner_name)).first()
        if owner:
            device.owner = owner


def _get_or_create_profile(user, name):
    if not name:
        return None
    profile = AddressBookProfile.objects.filter(Q(owner=user) & Q(name=name)).first()
    if profile:
        return profile
    profile = AddressBookProfile(
        guid=uuid.uuid4().hex,
        name=name,
        owner=user,
        rule=3,
    )
    profile.save()
    return profile


def _upsert_ab_peer(owner, guid, rid, data, is_personal):
    peer = RustDeskPeer.objects.filter(Q(uid=owner.id) & Q(rid=rid) & Q(profile_guid=guid)).first()
    tags = _safe_tags(data.get('tags', []))
    tags_str = ','.join(tags)
    if not peer:
        device = RustDesDevice.objects.filter(Q(rid=rid)).first()
        peer = RustDeskPeer(
            uid=owner.id,
            rid=rid,
            username=(device.username if device else ''),
            hostname=(device.hostname if device else ''),
            platform=(device.os if device else ''),
            alias=data.get('alias', ''),
            tags=tags_str,
            rhash=data.get('hash', '') if is_personal else '',
            password=data.get('password', '') if not is_personal else '',
            note=data.get('note', ''),
            device_group_name=data.get('device_group_name', ''),
            login_name=data.get('loginName', ''),
            same_server=bool(data.get('same_server', False)),
            profile_guid=guid,
        )
    else:
        if 'alias' in data:
            peer.alias = data.get('alias', peer.alias)
        if 'username' in data:
            peer.username = data.get('username', peer.username)
        if 'hostname' in data:
            peer.hostname = data.get('hostname', peer.hostname)
        if 'platform' in data:
            peer.platform = data.get('platform', peer.platform)
        if 'tags' in data:
            peer.tags = tags_str
        if 'note' in data:
            peer.note = data.get('note', peer.note)
        if 'device_group_name' in data:
            peer.device_group_name = data.get('device_group_name', peer.device_group_name)
        if 'loginName' in data:
            peer.login_name = data.get('loginName', peer.login_name)
        if is_personal:
            if 'hash' in data:
                peer.rhash = data.get('hash', peer.rhash)
        else:
            if 'password' in data:
                peer.password = data.get('password', peer.password)
    peer.save()
    return peer


def login(request):
    result = {}
    if request.method == 'GET':
        result['error'] = _('请求方式错误！请使用POST方式。')
        _log_event(request, 'api_login_invalid_method', level="warning")
        return JsonResponse(result)

    data = _load_json(request)

    username = str(data.get('username', '')).strip()
    password = data.get('password', '')
    rid = data.get('id', '')
    uuid = data.get('uuid', '')
    autoLogin = data.get('autoLogin', True)
    rtype = data.get('type', '')
    deviceInfo = data.get('deviceInfo', '')
    user = auth.authenticate(username=username, password=password)
    if not user:
        candidate = UserProfile.objects.filter(Q(username__iexact=username)).first()
        if candidate and candidate.check_password(password):
            candidate.backend = 'django.contrib.auth.backends.ModelBackend'
            user = candidate
        else:
            result['error'] = _('帐号或密码错误！请重试，多次重试后将被锁定IP！')
            reason = 'password_mismatch' if candidate else 'user_not_found'
            _log_event(request, 'api_login_failed', level="warning", username=username, reason=reason)
            return JsonResponse(result)
    if not user.is_active:
        _log_event(request, 'api_login_denied', level="warning", username=username, reason='inactive')
        return JsonResponse({'error': _('账号已被禁用')}, status=403)
    user.rid = rid
    user.uuid = uuid
    user.autoLogin = autoLogin
    user.rtype = rtype
    if isinstance(deviceInfo, (dict, list)):
        user.deviceInfo = json.dumps(deviceInfo, ensure_ascii=False)
    else:
        user.deviceInfo = str(deviceInfo)
    user.save()

    device = RustDesDevice.objects.filter(Q(rid=rid) & Q(uuid=uuid)).first()
    if device and not device.is_active:
        _log_event(request, 'api_login_denied', level="warning", username=username, reason='device_inactive', rid=rid)
        return JsonResponse({'error': 'Device disabled'}, status=403)
    if device and not user.is_admin and device.owner_id and device.owner_id != user.id:
        _log_event(request, 'api_login_denied', level="warning", username=username, reason='device_owner_mismatch', rid=rid)
        return JsonResponse({'error': 'Permission denied'}, status=403)
    if device:
        if device.owner_id is None or device.owner_id == user.id or user.is_admin:
            device.owner = user
            device.owner_name = user.username
        device.save()

    token = _issue_access_token(user)

    if rid:
        personal_guid = _personal_guid(user)
        peer = RustDeskPeer.objects.filter(Q(uid=user.id) & Q(rid=rid) & Q(profile_guid=personal_guid)).first()
        if not peer and device:
            RustDeskPeer.objects.create(
                uid=user.id,
                rid=device.rid,
                username=device.username or '',
                hostname=device.hostname or '',
                alias='',
                platform=device.os or '',
                tags='',
                rhash='',
                profile_guid=personal_guid,
            )

    result.update(_auth_body(user, token))
    _log_event(request, 'api_login_success', username=user.username, rid=rid)
    return JsonResponse(result)


def logout(request):
    if request.method == 'GET':
        result = {'error': _('请求方式错误！')}
        _log_event(request, 'api_logout_invalid_method', level="warning")
        return JsonResponse(result)

    data = _load_json(request)
    rid = data.get('id', '')
    uuid = data.get('uuid', '')
    token, user = _get_token_user(request)
    if not user and rid and uuid:
        user = UserProfile.objects.filter(Q(rid=rid) & Q(uuid=uuid)).first()
    if not user:
        result = {'error': _('异常请求！')}
        _log_event(request, 'api_logout_failed', level="warning")
        return JsonResponse(result)
    token = RustDeskToken.objects.filter(Q(uid=user.id) & Q(rid=user.rid)).first()
    if token:
        token.delete()

    result = {'code': 1}
    _log_event(request, 'api_logout_success', username=user.username, rid=user.rid)
    return JsonResponse(result)


def currentUser(request):
    result = {}
    if request.method == 'GET':
        result['error'] = _('错误的提交方式！')
        _log_event(request, 'api_current_user_invalid_method', level="warning")
        return JsonResponse(result)
    # postdata = json.loads(request.body)
    # rid = postdata.get('id', '')
    # uuid = postdata.get('uuid', '')

    token, user = _get_token_user(request)

    if not user:
        _log_event(request, 'api_current_user_failed', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    if token:
        result['access_token'] = token.access_token
    result['type'] = 'access_token'
    result['name'] = user.username
    result['status'] = 1 if user.is_active else 0
    result['is_admin'] = True if user.is_admin else False
    result['email'] = user.email or ''
    result['note'] = user.note or ''
    _log_event(request, 'api_current_user_success', username=user.username)
    return JsonResponse(result)


def ab(request):
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_ab_unauthorized', level="warning")
        return JsonResponse({'error': _('拉取列表错误！')}, status=401)
    guid = _personal_guid(user)

    if request.method == 'GET':
        result = {}
        tags = RustDeskTag.objects.filter(Q(uid=user.id) & Q(profile_guid=guid))
        tag_names = [str(x.tag_name) for x in tags]
        tag_colors = {str(x.tag_name): int(x.tag_color) for x in tags if x.tag_color != ''}

        peers = RustDeskPeer.objects.filter(Q(uid=user.id) & Q(profile_guid=guid))
        peers_result = []
        for peer in peers:
            tmp = {
                'id': peer.rid,
                'username': peer.username,
                'hostname': peer.hostname,
                'alias': peer.alias,
                'platform': peer.platform,
                'tags': [x for x in peer.tags.split(',') if x],
                'hash': peer.rhash,
            }
            peers_result.append(tmp)

        result['updated_at'] = timezone.now()
        result['data'] = json.dumps({
            'tags': tag_names,
            'peers': peers_result,
            'tag_colors': json.dumps(tag_colors)
        })
        _log_event(request, 'api_ab_fetch', level="debug", username=user.username, guid=guid, tags=len(tag_names), peers=len(peers_result))
        return JsonResponse(result)
    else:
        postdata = _load_json(request)
        data = postdata.get('data', '')
        try:
            data = {} if data == '' else json.loads(data)
        except Exception:
            _log_event(request, 'api_ab_update_failed', level="warning", username=user.username, guid=guid, reason='invalid_json')
            return JsonResponse({'error': 'Invalid data'}, status=400)
        tagnames = data.get('tags', [])
        tag_colors = data.get('tag_colors', '')
        tag_colors = {} if tag_colors == '' else json.loads(tag_colors)
        peers = data.get('peers', [])

        with transaction.atomic():
            RustDeskTag.objects.filter(Q(uid=user.id) & Q(profile_guid=guid)).delete()
            RustDeskPeer.objects.filter(Q(uid=user.id) & Q(profile_guid=guid)).delete()
            if tagnames:
                RustDeskTag.objects.bulk_create([
                    RustDeskTag(
                        uid=user.id,
                        tag_name=name,
                        tag_color=tag_colors.get(name, ''),
                        profile_guid=guid,
                    )
                    for name in tagnames
                ])
            if peers:
                newlist = []
                for one in peers:
                    newlist.append(RustDeskPeer(
                        uid=user.id,
                        rid=one['id'],
                        username=one.get('username', ''),
                        hostname=one.get('hostname', ''),
                        alias=one.get('alias', ''),
                        platform=one.get('platform', ''),
                        tags=','.join(_safe_tags(one.get('tags', []))),
                        rhash=one.get('hash', ''),
                        profile_guid=guid,
                    ))
                RustDeskPeer.objects.bulk_create(newlist)
        _log_event(request, 'api_ab_update', username=user.username, guid=guid, tags=len(tagnames), peers=len(peers))
    return HttpResponse('')


def sysinfo(request):
    # 客户端注册服务后，才会发送设备信息
    result = {}
    if request.method == 'GET':
        result['error'] = _('错误的提交方式！')
        _log_event(request, 'api_sysinfo_invalid_method', level="warning")
        return JsonResponse(result)
    client_ip = get_client_ip(request)
    postdata = _load_json(request)
    if not postdata.get('id') or not postdata.get('uuid'):
        _log_event(request, 'api_sysinfo_missing_id', level="warning")
        return HttpResponse('ID_NOT_FOUND')
    updates = _device_update_fields(postdata)
    owner_name = postdata.get('preset-username') or postdata.get('user_name', '')
    device = RustDesDevice.objects.filter(Q(rid=postdata['id']) & Q(uuid=postdata['uuid'])).first()
    if not device:
        device = RustDesDevice(
            rid=postdata['id'],
            cpu=updates.get('cpu', postdata.get('cpu', '-')),
            hostname=updates.get('hostname', postdata.get('hostname', postdata.get('device_name', '-'))),
            memory=updates.get('memory', postdata.get('memory', '-')),
            os=updates.get('os', postdata.get('os', '-')),
            username=updates.get('username', postdata.get('username', postdata.get('device_username', '-'))),
            uuid=postdata['uuid'],
            version=updates.get('version', postdata.get('version', '-')),
            ip_address=client_ip
        )
        for key, val in updates.items():
            setattr(device, key, val)
        _assign_owner(device, owner_name, link_user=False, allow_override=False)
        device.save()
    else:
        for key, val in updates.items():
            setattr(device, key, val)
        device.ip_address = client_ip
        _assign_owner(device, owner_name, link_user=False, allow_override=False)
        device.save()
    _log_event(request, 'api_sysinfo_updated', level="debug", rid=postdata.get('id', ''), uuid=postdata.get('uuid', ''))
    return HttpResponse('SYSINFO_UPDATED')


def heartbeat(request):
    postdata = _load_json(request)
    if not postdata.get('id') or not postdata.get('uuid'):
        _log_event(request, 'api_heartbeat_missing_id', level="warning")
        return JsonResponse({'error': 'ID_NOT_FOUND'})
    token = RustDeskToken.objects.filter(Q(rid=postdata['id']) & Q(uuid=postdata['uuid'])).first()
    device = RustDesDevice.objects.filter(Q(rid=postdata['id']) & Q(uuid=postdata['uuid'])).first()
    if device:
        if not device.is_active:
            _log_event(request, 'api_heartbeat_device_disabled', level="warning", rid=postdata.get('id', ''), uuid=postdata.get('uuid', ''))
            return JsonResponse({'error': 'Device disabled'}, status=403)
        client_ip = get_client_ip(request)
        device.ip_address = client_ip
        device.save()
    else:
        # create a placeholder device to avoid repeated ID_NOT_FOUND
        device = RustDesDevice(
            rid=postdata['id'],
            cpu='-',
            hostname='-',
            memory='-',
            os='-',
            username='-',
            uuid=postdata['uuid'],
            version='-',
            ip_address=get_client_ip(request)
        )
        device.save()

    owner_hint = ''
    if device:
        if device.owner_name:
            owner_hint = device.owner_name
        elif device.owner:
            owner_hint = device.owner.username
    if not owner_hint and token and token.username:
        owner_hint = token.username

    # token保活
    expires_at = timezone.now() + datetime.timedelta(seconds=EFFECTIVE_SECONDS)
    RustDeskToken.objects.filter(Q(rid=postdata['id']) & Q(uuid=postdata['uuid'])).update(expires_at=expires_at)
    response = {}
    try:
        client_modified = int(postdata.get('modified_at', 0))
    except Exception:
        client_modified = 0
    if device and device.strategy_name:
        profile = StrategyProfile.objects.filter(Q(name=device.strategy_name)).first()
        if profile and profile.enabled:
            server_modified = int(profile.updated_at.timestamp())
            if server_modified != client_modified:
                response['modified_at'] = server_modified
                try:
                    options = json.loads(profile.config_options) if profile.config_options else {}
                except Exception:
                    options = {}
                response['strategy'] = {'config_options': options, 'extra': {}}
    if owner_hint:
        _log_event(request, 'api_heartbeat', level="debug", username=owner_hint, rid=postdata.get('id', ''), uuid=postdata.get('uuid', ''))
    else:
        _log_event(request, 'api_heartbeat', level="debug", rid=postdata.get('id', ''), uuid=postdata.get('uuid', ''))
    return JsonResponse(response)


def sysinfo_ver(request):
    _log_event(request, 'api_sysinfo_ver', level="debug")
    return HttpResponse('1')


def login_options(request):
    _log_event(request, 'api_login_options', level="debug")
    providers = getattr(settings, "OIDC_PROVIDERS", {})
    return JsonResponse([f"oidc/{name}" for name in providers.keys()], safe=False)


def oidc_auth(request):
    if request.method != 'POST':
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')}, status=405)
    data = _load_json(request)
    provider_name = _oidc_provider_name(data.get('op'))
    provider = getattr(settings, "OIDC_PROVIDERS", {}).get(provider_name)
    if not provider:
        _log_event(request, 'api_oidc_auth_unknown_provider', level="warning", op=provider_name)
        return JsonResponse({'error': 'OIDC provider is not configured'}, status=404)
    state = secrets.token_urlsafe(24)
    try:
        client = OAuth2Session(
            provider["client_id"],
            provider["client_secret"],
            scope=provider.get("scope", "openid email profile"),
            redirect_uri=provider["redirect_uri"],
        )
        metadata = client.load_server_metadata(f'{provider["issuer"].rstrip("/")}/.well-known/openid-configuration')
        auth_url = client.create_authorization_url(metadata["authorization_endpoint"], state=state)[0]
    except Exception as exc:
        _log_event(request, 'api_oidc_auth_failed', level="warning", op=provider_name, error=str(exc))
        return JsonResponse({'error': 'Failed to initialize OIDC authorization'}, status=502)
    now = timezone.now()
    stale_states = [
        key for key, value in OIDC_PENDING.items()
        if now - value.get("created_at", now) > datetime.timedelta(minutes=5)
    ]
    for key in stale_states:
        OIDC_PENDING.pop(key, None)
    OIDC_PENDING[state] = {
        "provider": provider_name,
        "created_at": now,
        "id": str(data.get("id", "")),
        "uuid": str(data.get("uuid", "")),
        "deviceInfo": data.get("deviceInfo", ""),
        "status": "pending",
    }
    _log_event(request, 'api_oidc_auth_created', level="debug", op=provider_name)
    return JsonResponse({'code': state, 'url': auth_url})


def oidc_auth_query(request):
    state = str(request.GET.get('code', '')).strip()
    session = OIDC_PENDING.get(state)
    if not session:
        return JsonResponse({'error': 'No authed oidc is found'})
    if timezone.now() - session["created_at"] > datetime.timedelta(minutes=3):
        OIDC_PENDING.pop(state, None)
        return JsonResponse({'error': 'OIDC authorization timeout'}, status=408)
    if session.get("status") == "error":
        error = session.get("error", "OIDC authorization failed")
        OIDC_PENDING.pop(state, None)
        return JsonResponse({'error': error}, status=400)
    if session.get("status") != "done":
        return JsonResponse({'error': 'No authed oidc is found'})
    body = session.get("body") or {}
    OIDC_PENDING.pop(state, None)
    return JsonResponse(body)


def oidc_callback(request):
    state = str(request.GET.get('state', '')).strip()
    code = str(request.GET.get('code', '')).strip()
    session = OIDC_PENDING.get(state)
    if not state or not code or not session:
        return HttpResponse('Invalid OIDC callback', status=400)
    provider = getattr(settings, "OIDC_PROVIDERS", {}).get(session["provider"])
    if not provider:
        session["status"] = "error"
        session["error"] = "OIDC provider is not configured"
        return HttpResponse('OIDC provider is not configured', status=400)
    try:
        client = OAuth2Session(
            provider["client_id"],
            provider["client_secret"],
            scope=provider.get("scope", "openid email profile"),
            redirect_uri=provider["redirect_uri"],
        )
        metadata = client.load_server_metadata(f'{provider["issuer"].rstrip("/")}/.well-known/openid-configuration')
        client.fetch_token(metadata["token_endpoint"], code=code)
        userinfo = client.get(metadata["userinfo_endpoint"]).json()
        username = (
            userinfo.get("preferred_username")
            or userinfo.get("email")
            or userinfo.get("sub")
            or ""
        ).strip()
        if not username:
            raise ValueError("OIDC user has no stable username")
        email = str(userinfo.get("email", "")).strip()
        user, created = UserProfile.objects.get_or_create(username=username, defaults={"email": email})
        if email and user.email != email:
            user.email = email
        if created:
            user.set_unusable_password()
        user.rid = session.get("id", "")
        user.uuid = session.get("uuid", "")
        device_info = session.get("deviceInfo", "")
        user.deviceInfo = json.dumps(device_info, ensure_ascii=False) if isinstance(device_info, (dict, list)) else str(device_info)
        user.save()
        if not user.is_active:
            raise PermissionError("Account is disabled")
        token = _issue_access_token(user)
        session["body"] = _auth_body(user, token)
        session["status"] = "done"
        _log_event(request, 'api_oidc_callback_success', username=user.username)
    except Exception as exc:
        session["status"] = "error"
        session["error"] = str(exc)
        _log_event(request, 'api_oidc_callback_failed', level="warning", error=str(exc))
        return HttpResponse('OIDC authorization failed', status=400)
    return HttpResponse('OIDC authorization completed. You can close this window.')


def devices_cli(request):
    if request.method == 'GET':
        _log_event(request, 'api_devices_cli_invalid_method', level="warning")
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')})
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_devices_cli_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    postdata = _load_json(request)
    rid = postdata.get('id', '')
    uuid = postdata.get('uuid', '')
    if not rid or not uuid:
        _log_event(request, 'api_devices_cli_missing_id', level="warning")
        return JsonResponse({'error': 'ID_NOT_FOUND'}, status=400)
    owner_name = postdata.get('user_name', '')
    if owner_name and not user.is_admin and owner_name != user.username:
        _log_event(request, 'api_devices_cli_denied', level="warning", username=user.username, rid=rid, reason='owner_mismatch')
        return JsonResponse({'error': 'Admin required'}, status=403)
    updates = _device_update_fields(postdata)
    ab_name = postdata.get('address_book_name', '')
    ab_tag = postdata.get('address_book_tag', '')
    ab_alias = postdata.get('address_book_alias', '')
    ab_password = postdata.get('address_book_password', '')
    ab_note = postdata.get('address_book_note', '')
    requires_ab = any([ab_name, ab_tag, ab_alias, ab_password, ab_note])

    device = RustDesDevice.objects.filter(Q(rid=rid) & Q(uuid=uuid)).first()
    if device and not user.is_admin and device.owner_id and device.owner_id != user.id:
        _log_event(request, 'api_devices_cli_denied', level="warning", username=user.username, rid=rid, reason='device_owner_mismatch')
        return JsonResponse({'error': 'Permission denied'}, status=403)

    try:
        with transaction.atomic():
            if not device:
                device = RustDesDevice(
                    rid=rid,
                    cpu=updates.get('cpu', '-'),
                    hostname=updates.get('hostname', postdata.get('device_name', '-')),
                    memory=updates.get('memory', '-'),
                    os=updates.get('os', '-'),
                    username=updates.get('username', postdata.get('device_username', '-')),
                    uuid=uuid,
                    version=updates.get('version', '-'),
                    ip_address=get_client_ip(request)
                )
            for key, val in updates.items():
                setattr(device, key, val)
            _assign_owner(device, owner_name)
            device.save()

            if requires_ab:
                if not device.owner:
                    raise ValueError('Invalid user_name')
                profile = _get_or_create_profile(device.owner, ab_name) if ab_name else None
                guid = profile.guid if profile else _personal_guid(device.owner)
                is_personal = guid == _personal_guid(device.owner)
                tags = [ab_tag] if ab_tag else []
                peer_data = {
                    'alias': ab_alias,
                    'tags': tags,
                    'note': ab_note,
                }
                if ab_password:
                    if is_personal:
                        peer_data['hash'] = ab_password
                    else:
                        peer_data['password'] = ab_password
                _upsert_ab_peer(device.owner, guid, rid, peer_data, is_personal)
                if ab_tag:
                    RustDeskTag.objects.get_or_create(
                        uid=device.owner.id,
                        tag_name=ab_tag,
                        profile_guid=guid,
                        defaults={'tag_color': ''},
                    )
    except ValueError:
        _log_event(request, 'api_devices_cli_failed', level="warning", username=user.username, rid=rid, reason='invalid_user_name')
        return JsonResponse({'error': 'Invalid user_name'}, status=400)
    _log_event(request, 'api_devices_cli_updated', username=user.username, rid=rid)
    return HttpResponse('')


def devices_deploy(request):
    if request.method != 'POST':
        _log_event(request, 'api_devices_deploy_invalid_method', level="warning")
        return JsonResponse({'result': 'INVALID_INPUT'}, status=405)
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_devices_deploy_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    postdata = _load_json(request)
    rid = str(postdata.get('id', '')).strip()
    uuid_value = str(postdata.get('uuid', '')).strip()
    pk = str(postdata.get('pk', '')).strip()
    if (
        not _valid_deploy_text(rid, min_len=6, max_len=60)
        or not _valid_deploy_text(uuid_value, max_len=100)
        or not _valid_deploy_text(pk, max_len=MAX_DEPLOY_KEY_LEN)
    ):
        _log_event(request, 'api_devices_deploy_invalid_input', level="warning", username=user.username, rid=rid)
        return JsonResponse({'result': 'INVALID_INPUT'}, status=400)

    conflict = RustDesDevice.objects.filter(Q(rid=rid)).exclude(Q(uuid=uuid_value)).first()
    if conflict:
        _log_event(request, 'api_devices_deploy_id_taken', level="warning", username=user.username, rid=rid)
        return JsonResponse({'result': 'ID_TAKEN'})

    with transaction.atomic():
        device = RustDesDevice.objects.select_for_update().filter(Q(uuid=uuid_value)).first()
        if device and device.owner_id and device.owner_id != user.id and not user.is_admin:
            _log_event(request, 'api_devices_deploy_denied', level="warning", username=user.username, rid=rid)
            return JsonResponse({'error': 'Permission denied'}, status=403)
        if not device:
            device = RustDesDevice(
                rid=rid,
                cpu='-',
                hostname='-',
                memory='-',
                os='-',
                uuid=uuid_value,
                username='',
                version='-',
                ip_address=get_client_ip(request),
            )
        device.rid = rid
        device.uuid = uuid_value
        device.owner = user
        device.owner_name = user.username
        device.ip_address = get_client_ip(request)
        device.save()

    _log_event(request, 'api_devices_deploy_ok', username=user.username, rid=rid)
    return JsonResponse({'result': 'OK'})


def plugin_sign(request):
    if request.method != 'POST':
        _log_event(request, 'api_plugin_sign_invalid_method', level="warning")
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')}, status=405)
    signing_key = _plugin_signing_key()
    if signing_key is None:
        _log_event(request, 'api_plugin_sign_not_configured', level="warning")
        return JsonResponse({'error': 'Plugin signing key is not configured'}, status=503)
    postdata = _load_json(request)
    msg = postdata.get('msg', [])
    if not isinstance(msg, list) or len(msg) > MAX_PLUGIN_SIGN_MSG_BYTES:
        _log_event(request, 'api_plugin_sign_invalid_msg', level="warning")
        return JsonResponse({'error': 'Invalid msg'}, status=400)
    for item in msg:
        if not isinstance(item, int) or item < 0 or item > 255:
            _log_event(request, 'api_plugin_sign_invalid_byte', level="warning")
            return JsonResponse({'error': 'Invalid msg'}, status=400)
    signed_msg = signing_key.sign(bytes(msg)).signed_message
    _log_event(
        request,
        'api_plugin_sign_ok',
        level="debug",
        plugin_id=str(postdata.get('plugin_id', '')),
        version=str(postdata.get('version', '')),
    )
    return JsonResponse({'signed_msg': list(signed_msg)})


def record(request):
    if request.method != 'POST':
        _log_event(request, 'api_record_invalid_method', level="warning")
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')})
    record_type = request.GET.get('type', '')
    filename = _safe_record_name(request.GET.get('file', ''))
    if not filename:
        _log_event(request, 'api_record_invalid_file', level="warning")
        return JsonResponse({'error': 'Invalid file'}, status=400)
    base_dir = _record_dir()
    os.makedirs(base_dir, exist_ok=True)
    filepath = os.path.join(base_dir, filename)
    if record_type == 'new':
        with open(filepath, 'wb'):
            pass
        _log_event(request, 'api_record_new', level="info", file=filename)
        return HttpResponse('')
    if record_type in ('part', 'tail'):
        try:
            offset = int(request.GET.get('offset', '0'))
        except Exception:
            offset = 0
        if offset < 0:
            offset = 0
        data = request.body or b''
        mode = 'r+b' if os.path.exists(filepath) else 'wb+'
        with open(filepath, mode) as f:
            if offset > 0:
                f.seek(offset)
            f.write(data)
        _log_event(request, 'api_record_write', level="debug", file=filename, offset=offset, size=len(data))
        return HttpResponse('')
    if record_type == 'remove':
        try:
            os.remove(filepath)
        except FileNotFoundError:
            pass
        _log_event(request, 'api_record_remove', level="info", file=filename)
        return HttpResponse('')
    return JsonResponse({'error': 'Invalid type'}, status=400)


def audit_with_type(request, typ):
    _log_event(request, 'api_audit_dispatch', level="debug", typ=typ)
    if request.method == 'GET':
        if typ.startswith('conn/active'):
            return _audit_conn_active(request)
        return JsonResponse('', safe=False)
    if typ == 'conn':
        return _audit_conn(request)
    if typ == 'file':
        return _audit_file(request)
    if typ == 'alarm':
        return _audit_alarm(request)
    _log_event(request, 'api_audit_unknown', level="warning", typ=typ)
    return _audit_conn(request)


def audit_note(request):
    if request.method != 'PUT':
        _log_event(request, 'api_audit_note_invalid_method', level="warning")
        return JsonResponse({'error': _('请求方式错误！')})
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_audit_note_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    postdata = _load_json(request)
    guid = postdata.get('guid', '')
    note = postdata.get('note', '')
    if not guid:
        _log_event(request, 'api_audit_note_invalid_guid', level="warning")
        return JsonResponse({'error': 'Invalid guid'}, status=400)
    AuditSession.objects.filter(Q(guid=guid)).update(note=note)
    _log_event(request, 'api_audit_note_update', username=user.username, guid=guid)
    return JsonResponse({'code': 1, 'data': 'ok'})


def audit_root(request):
    if request.method == 'PUT':
        return audit_note(request)
    if request.method == 'GET':
        _log_event(request, 'api_audit_root_get', level="debug")
        return JsonResponse('', safe=False)
    return _audit_conn(request)


def ab_settings(request):
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_ab_settings_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    _log_event(request, 'api_ab_settings', level="debug", username=user.username)
    return JsonResponse({'max_peer_one_ab': 0})


def ab_personal(request):
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_ab_personal_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    profile = _ensure_personal_profile(user)
    _log_event(request, 'api_ab_personal', level="debug", username=user.username)
    return JsonResponse({'guid': _personal_guid(user), 'name': profile.name})


def ab_shared_profiles(request):
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_ab_shared_profiles_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    try:
        current = int(request.GET.get('current', 1))
        page_size = int(request.GET.get('pageSize', 100))
    except Exception:
        current = 1
        page_size = 100
    items = {}

    def add_profile(p, rule_value):
        if not p or _is_personal_guid(p.guid):
            return
        try:
            info = json.loads(p.info) if p.info else None
        except Exception:
            info = p.info
        owner_name = p.owner.username if p.owner else ''
        existing = items.get(p.guid)
        rule_value = int(rule_value or 0)
        if existing:
            if rule_value > existing.get('rule', 0):
                existing['rule'] = rule_value
            return
        items[p.guid] = {
            'guid': p.guid,
            'name': p.name,
            'owner': owner_name,
            'note': p.note,
            'info': info,
            'rule': rule_value,
        }

    if user.is_admin:
        for p in AddressBookProfile.objects.all():
            add_profile(p, 3)
    else:
        for p in AddressBookProfile.objects.filter(Q(owner=user)):
            add_profile(p, 3)
        for share in AddressBookShare.objects.filter(Q(user=user)).select_related('profile', 'profile__owner'):
            add_profile(share.profile, share.rule)
        group_ids = list(user.groups.values_list('id', flat=True))
        rules_qs = AddressBookRule.objects.filter(Q(is_everyone=True))
        if group_ids:
            rules_qs = rules_qs | AddressBookRule.objects.filter(Q(group_id__in=group_ids))
        rules_qs = rules_qs | AddressBookRule.objects.filter(Q(user=user))
        for r in rules_qs.select_related('profile', 'profile__owner'):
            add_profile(r.profile, r.rule)
    data = list(items.values())
    data.sort(key=lambda x: x.get('name', ''))
    total = len(data)
    start = (current - 1) * page_size
    end = start + page_size
    _log_event(request, 'api_ab_shared_profiles', level="debug", username=user.username, total=total, page=current, page_size=page_size)
    return JsonResponse({'total': total, 'data': data[start:end]})


def ab_shared_add(request):
    if request.method == 'GET':
        _log_event(request, 'api_ab_shared_add_invalid_method', level="warning")
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')})
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_ab_shared_add_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    postdata = _load_json(request)
    name = str(postdata.get('name', '')).strip()
    note = postdata.get('note', '')
    info = postdata.get('info', None)
    if not name:
        _log_event(request, 'api_ab_shared_add_failed', level="warning", username=user.username, reason='missing_name')
        return JsonResponse({'error': 'Invalid name'}, status=400)
    if _is_reserved_ab_profile_name(name):
        return JsonResponse({'error': 'Reserved name'}, status=400)
    profile = AddressBookProfile.objects.filter(Q(owner=user) & Q(name=name)).first()
    if not profile:
        profile = AddressBookProfile(
            guid=uuid.uuid4().hex,
            name=name,
            owner=user,
            rule=3,
            note=note or '',
        )
    if info is not None:
        if isinstance(info, (dict, list)):
            profile.info = json.dumps(info, ensure_ascii=False)
        else:
            profile.info = str(info)
    if note is not None:
        profile.note = note
    profile.save()
    _log_event(request, 'api_ab_shared_add', username=user.username, guid=profile.guid, name=name)
    return JsonResponse({'code': 1, 'guid': profile.guid})


def ab_shared_update_profile(request):
    if request.method == 'GET':
        _log_event(request, 'api_ab_shared_update_invalid_method', level="warning")
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')})
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_ab_shared_update_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    postdata = _load_json(request)
    guid = postdata.get('guid', '')
    if not guid:
        return JsonResponse({'error': 'Invalid guid'}, status=400)
    profile = AddressBookProfile.objects.filter(Q(guid=guid)).first()
    if not profile:
        return JsonResponse({'error': 'Not found'}, status=404)
    if _is_personal_guid(profile.guid):
        return JsonResponse({'error': 'Personal address book cannot be modified'}, status=403)
    if not user.is_admin and str(profile.owner_id) != str(user.id):
        return JsonResponse({'error': 'No access'}, status=403)
    if 'name' in postdata and postdata.get('name'):
        profile.name = postdata.get('name')
    if 'note' in postdata and postdata.get('note') is not None:
        profile.note = postdata.get('note')
    if 'info' in postdata and postdata.get('info') is not None:
        info = postdata.get('info')
        if isinstance(info, (dict, list)):
            profile.info = json.dumps(info, ensure_ascii=False)
        else:
            profile.info = str(info)
    if 'owner' in postdata and postdata.get('owner'):
        if not user.is_admin:
            return JsonResponse({'error': 'Only admin can transfer owner'}, status=403)
        owner = UserProfile.objects.filter(Q(username=postdata.get('owner')) | Q(id=postdata.get('owner'))).first()
        if not owner:
            return JsonResponse({'error': 'Owner not found'}, status=404)
        profile.owner = owner
    profile.save()
    _log_event(request, 'api_ab_shared_update', username=user.username, guid=guid)
    return JsonResponse({'code': 1, 'data': 'ok'})


def ab_shared_delete(request):
    if request.method == 'GET':
        _log_event(request, 'api_ab_shared_delete_invalid_method', level="warning")
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')})
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_ab_shared_delete_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    postdata = _load_json(request)
    if not isinstance(postdata, list):
        return JsonResponse({'error': 'Invalid data'}, status=400)
    deleted = 0
    for guid in postdata:
        profile = AddressBookProfile.objects.filter(Q(guid=guid)).first()
        if not profile:
            continue
        if _is_personal_guid(profile.guid):
            continue
        if not user.is_admin and str(profile.owner_id) != str(user.id):
            continue
        RustDeskPeer.objects.filter(Q(profile_guid=guid)).delete()
        RustDeskTag.objects.filter(Q(profile_guid=guid)).delete()
        AddressBookRule.objects.filter(Q(profile=profile)).delete()
        AddressBookShare.objects.filter(Q(profile=profile)).delete()
        profile.delete()
        deleted += 1
    _log_event(request, 'api_ab_shared_delete', username=user.username, count=deleted)
    return JsonResponse({'code': 1, 'deleted': deleted})


def ab_rules(request):
    if request.method == 'DELETE':
        return ab_rules_delete(request)
    token, user = _get_token_user(request)
    if not user:
        session_user = getattr(request, 'user', None)
        if session_user and getattr(session_user, 'is_authenticated', False):
            return HttpResponseRedirect('/api/ab_rules')
        _log_event(request, 'api_ab_rules_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    guid = request.GET.get('ab', '') or request.GET.get('guid', '')
    if not guid:
        return JsonResponse({'error': 'Invalid guid'}, status=400)
    profile, owner, rule = _get_profile_access(user, guid)
    if not owner and not user.is_admin:
        _log_event(request, 'api_ab_rules_denied', level="warning", username=user.username, guid=guid)
        return JsonResponse({'error': 'No access'}, status=403)
    try:
        current = int(request.GET.get('current', 1))
        page_size = int(request.GET.get('pageSize', 100))
    except Exception:
        current = 1
        page_size = 100
    data = []
    shares = AddressBookShare.objects.filter(Q(profile=profile)).select_related('user')
    for share in shares:
        data.append({
            'guid': share.guid,
            'rule': share.rule,
            'user': share.user.username if share.user else '',
        })
    rules = AddressBookRule.objects.filter(Q(profile=profile)).select_related('user', 'group')
    for one in rules:
        data.append({
            'guid': one.guid,
            'rule': one.rule,
            'user': one.user.username if one.user_id else '',
            'group': one.group.name if one.group_id else '',
        })
    total = len(data)
    start = (current - 1) * page_size
    end = start + page_size
    _log_event(request, 'api_ab_rules', level="debug", username=user.username, guid=guid, total=total)
    return JsonResponse({'total': total, 'data': data[start:end]})


def ab_rule(request):
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_ab_rule_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    if request.method == 'GET':
        return JsonResponse({'error': _('请求方式错误！')}, status=405)
    postdata = _load_json(request)
    if request.method == 'POST':
        guid = postdata.get('guid', '')
        rule_value = int(postdata.get('rule', 1) or 1)
        if not guid:
            return JsonResponse({'error': 'Invalid guid'}, status=400)
        profile = AddressBookProfile.objects.filter(Q(guid=guid)).first()
        if not profile:
            return JsonResponse({'error': 'Not found'}, status=404)
        if _is_personal_guid(profile.guid):
            return JsonResponse({'error': 'Personal address book cannot be shared'}, status=403)
        if not user.is_admin and str(profile.owner_id) != str(user.id):
            return JsonResponse({'error': 'No access'}, status=403)
        user_name = postdata.get('user', '')
        group_name = postdata.get('group', '')
        if user_name:
            target_user = UserProfile.objects.filter(Q(username=user_name) | Q(id=user_name)).first()
            if not target_user:
                return JsonResponse({'error': 'User not found'}, status=404)
            share = AddressBookShare.objects.filter(Q(profile=profile) & Q(user=target_user)).first()
            created = False
            if not share:
                share = AddressBookShare(profile=profile, user=target_user, rule=rule_value)
                created = True
            else:
                share.rule = rule_value
            share.save()
            _audit_ab_rule(profile, user, 'share_add' if created else 'share_update', 'user', target_user.username, rule_value, {'guid': share.guid})
            _log_event(request, 'api_ab_rule_add', username=user.username, guid=guid, rule=rule_value, user=target_user.username)
            return JsonResponse({'guid': share.guid, 'rule': share.rule})
        if group_name:
            group = Group.objects.filter(Q(name=group_name)).first()
            if not group:
                return JsonResponse({'error': 'Group not found'}, status=404)
            rule_obj = AddressBookRule.objects.filter(Q(profile=profile) & Q(group=group)).first()
            created = False
            if not rule_obj:
                rule_obj = AddressBookRule(profile=profile, group=group, rule=rule_value, is_everyone=False)
                created = True
            else:
                rule_obj.rule = rule_value
            rule_obj.save()
            _audit_ab_rule(profile, user, 'rule_add' if created else 'rule_update', 'group', group.name, rule_value, {'guid': rule_obj.guid})
            _log_event(request, 'api_ab_rule_add', username=user.username, guid=guid, rule=rule_value, group=group.name)
            return JsonResponse({'guid': rule_obj.guid, 'rule': rule_obj.rule})
        rule_obj = AddressBookRule.objects.filter(Q(profile=profile) & Q(is_everyone=True)).first()
        created = False
        if not rule_obj:
            rule_obj = AddressBookRule(profile=profile, rule=rule_value, is_everyone=True)
            created = True
        else:
            rule_obj.rule = rule_value
        rule_obj.save()
        _audit_ab_rule(profile, user, 'rule_add' if created else 'rule_update', 'everyone', 'Everyone', rule_value, {'guid': rule_obj.guid})
        _log_event(request, 'api_ab_rule_add', username=user.username, guid=guid, rule=rule_value, target='everyone')
        return JsonResponse({'guid': rule_obj.guid, 'rule': rule_obj.rule})
    if request.method == 'PATCH':
        rule_guid = postdata.get('guid', '')
        rule_value = int(postdata.get('rule', 1) or 1)
        if not rule_guid:
            return JsonResponse({'error': 'Invalid guid'}, status=400)
        share = AddressBookShare.objects.filter(Q(guid=rule_guid)).select_related('profile').first()
        if share:
            profile = share.profile
            if not user.is_admin and str(profile.owner_id) != str(user.id):
                return JsonResponse({'error': 'No access'}, status=403)
            share.rule = rule_value
            share.save()
            target_name = share.user.username if share.user else ''
            _audit_ab_rule(profile, user, 'share_update', 'user', target_name, rule_value, {'guid': share.guid})
            _log_event(request, 'api_ab_rule_update', username=user.username, guid=rule_guid, rule=rule_value)
            return JsonResponse({'code': 1})
        rule_obj = AddressBookRule.objects.filter(Q(guid=rule_guid)).select_related('profile').first()
        if not rule_obj:
            return JsonResponse({'error': 'Not found'}, status=404)
        profile = rule_obj.profile
        if not user.is_admin and str(profile.owner_id) != str(user.id):
            return JsonResponse({'error': 'No access'}, status=403)
        rule_obj.rule = rule_value
        rule_obj.save()
        if rule_obj.is_everyone:
            target_type = 'everyone'
            target_name = 'Everyone'
        elif rule_obj.group_id:
            target_type = 'group'
            target_name = rule_obj.group.name if rule_obj.group else ''
        else:
            target_type = 'user'
            target_name = rule_obj.user.username if rule_obj.user else ''
        _audit_ab_rule(profile, user, 'rule_update', target_type, target_name, rule_value, {'guid': rule_obj.guid})
        _log_event(request, 'api_ab_rule_update', username=user.username, guid=rule_guid, rule=rule_value)
        return JsonResponse({'code': 1})
    return JsonResponse({'error': _('请求方式错误！')}, status=405)


def ab_rules_delete(request):
    if request.method == 'GET':
        _log_event(request, 'api_ab_rules_delete_invalid_method', level="warning")
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')})
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_ab_rules_delete_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    postdata = _load_json(request)
    if not isinstance(postdata, list):
        return JsonResponse({'error': 'Invalid data'}, status=400)
    deleted = 0
    for rule_guid in postdata:
        share = AddressBookShare.objects.filter(Q(guid=rule_guid)).select_related('profile').first()
        if share:
            profile = share.profile
            if user.is_admin or str(profile.owner_id) == str(user.id):
                target_name = share.user.username if share.user else ''
                _audit_ab_rule(profile, user, 'share_delete', 'user', target_name, share.rule, {'guid': share.guid})
                share.delete()
                deleted += 1
            continue
        rule_obj = AddressBookRule.objects.filter(Q(guid=rule_guid)).select_related('profile').first()
        if rule_obj:
            profile = rule_obj.profile
            if user.is_admin or str(profile.owner_id) == str(user.id):
                if rule_obj.is_everyone:
                    target_type = 'everyone'
                    target_name = 'Everyone'
                elif rule_obj.group_id:
                    target_type = 'group'
                    target_name = rule_obj.group.name if rule_obj.group else ''
                else:
                    target_type = 'user'
                    target_name = rule_obj.user.username if rule_obj.user else ''
                _audit_ab_rule(profile, user, 'rule_delete', target_type, target_name, rule_obj.rule, {'guid': rule_obj.guid})
                rule_obj.delete()
                deleted += 1
    _log_event(request, 'api_ab_rules_delete', username=user.username, count=deleted)
    return JsonResponse({'code': 1, 'deleted': deleted})


def ab_peers(request):
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_ab_peers_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    guid = request.GET.get('ab', '') or _personal_guid(user)
    profile, owner, rule = _get_profile_access(user, guid)
    if guid == _personal_guid(user):
        _ensure_personal_profile(user)
        owner = user
    if not owner:
        _log_event(request, 'api_ab_peers_denied', level="warning", username=user.username, guid=guid)
        return JsonResponse({'error': 'No access'}, status=403)
    try:
        current = int(request.GET.get('current', 1))
        page_size = int(request.GET.get('pageSize', 100))
    except Exception:
        current = 1
        page_size = 100
    qs = RustDeskPeer.objects.filter(Q(uid=owner.id) & Q(profile_guid=guid)).order_by('rid')
    total = qs.count()
    start = (current - 1) * page_size
    end = start + page_size
    data = []
    is_personal = guid == _personal_guid(owner)
    for p in qs[start:end]:
        tags = [x for x in p.tags.split(',') if x]
        item = {
            'id': p.rid,
            'username': p.username,
            'hostname': p.hostname,
            'platform': p.platform,
            'alias': p.alias,
            'tags': tags,
            'note': p.note,
            'device_group_name': p.device_group_name,
            'loginName': p.login_name,
            'same_server': p.same_server,
        }
        if is_personal:
            item['hash'] = p.rhash
            item['password'] = ''
        else:
            item['hash'] = ''
            item['password'] = p.password
        data.append(item)
    _log_event(request, 'api_ab_peers', level="debug", username=user.username, guid=guid, total=total, page=current, page_size=page_size)
    return JsonResponse({'total': total, 'data': data})


def ab_tags(request, guid):
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_ab_tags_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    profile, owner, rule = _get_profile_access(user, guid)
    if guid == _personal_guid(user):
        _ensure_personal_profile(user)
        owner = user
    if not owner:
        _log_event(request, 'api_ab_tags_denied', level="warning", username=user.username, guid=guid)
        return JsonResponse({'error': 'No access'}, status=403)
    tags = RustDeskTag.objects.filter(Q(uid=owner.id) & Q(profile_guid=guid))
    data = []
    for t in tags:
        try:
            color = int(t.tag_color)
        except Exception:
            color = 0
        data.append({'name': t.tag_name, 'color': color})
    _log_event(request, 'api_ab_tags', level="debug", username=user.username, guid=guid, total=len(data))
    return JsonResponse(data, safe=False)


def ab_peer_add(request, guid):
    if request.method == 'GET':
        _log_event(request, 'api_ab_peer_add_invalid_method', level="warning", guid=guid)
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')})
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_ab_peer_add_unauthorized', level="warning", guid=guid)
        return JsonResponse({'error': 'Invalid token'}, status=401)
    profile, owner, rule = _get_profile_access(user, guid)
    if guid == _personal_guid(user):
        _ensure_personal_profile(user)
        owner = user
        rule = 3
    if not owner:
        _log_event(request, 'api_ab_peer_add_denied', level="warning", username=user.username, guid=guid)
        return JsonResponse({'error': 'No access'}, status=403)
    if not _can_write_rule(rule):
        _log_event(request, 'api_ab_peer_add_denied', level="warning", username=user.username, guid=guid, reason='read_only')
        return JsonResponse({'error': 'Read-only'}, status=403)
    postdata = _load_json(request)
    rid = postdata.get('id', '')
    if not rid:
        _log_event(request, 'api_ab_peer_add_failed', level="warning", username=user.username, guid=guid, reason='missing_id')
        return JsonResponse({'error': 'ID_NOT_FOUND'}, status=400)
    is_personal = guid == _personal_guid(owner)
    peer_data = dict(postdata)
    if is_personal:
        peer_data.pop('password', None)
    else:
        peer_data.pop('hash', None)
    _upsert_ab_peer(owner, guid, rid, peer_data, is_personal)
    _log_event(request, 'api_ab_peer_add', username=user.username, guid=guid, rid=rid)
    return HttpResponse('')


def ab_peer_update(request, guid):
    if request.method == 'GET':
        _log_event(request, 'api_ab_peer_update_invalid_method', level="warning", guid=guid)
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')})
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_ab_peer_update_unauthorized', level="warning", guid=guid)
        return JsonResponse({'error': 'Invalid token'}, status=401)
    profile, owner, rule = _get_profile_access(user, guid)
    if guid == _personal_guid(user):
        _ensure_personal_profile(user)
        owner = user
        rule = 3
    if not owner:
        _log_event(request, 'api_ab_peer_update_denied', level="warning", username=user.username, guid=guid)
        return JsonResponse({'error': 'No access'}, status=403)
    if not _can_write_rule(rule):
        _log_event(request, 'api_ab_peer_update_denied', level="warning", username=user.username, guid=guid, reason='read_only')
        return JsonResponse({'error': 'Read-only'}, status=403)
    postdata = _load_json(request)
    rid = postdata.get('id', '')
    if not rid:
        _log_event(request, 'api_ab_peer_update_failed', level="warning", username=user.username, guid=guid, reason='missing_id')
        return JsonResponse({'error': 'ID_NOT_FOUND'}, status=400)
    is_personal = guid == _personal_guid(owner)
    peer_data = dict(postdata)
    if is_personal:
        peer_data.pop('password', None)
    else:
        peer_data.pop('hash', None)
    peer = RustDeskPeer.objects.filter(Q(uid=owner.id) & Q(rid=rid) & Q(profile_guid=guid)).first()
    if not peer:
        _log_event(request, 'api_ab_peer_update_failed', level="warning", username=user.username, guid=guid, rid=rid, reason='not_found')
        return JsonResponse({'error': 'ID_NOT_FOUND'}, status=404)
    _upsert_ab_peer(owner, guid, rid, peer_data, is_personal)
    _log_event(request, 'api_ab_peer_update', username=user.username, guid=guid, rid=rid)
    return HttpResponse('')


def ab_peer_delete(request, guid):
    if request.method == 'GET':
        _log_event(request, 'api_ab_peer_delete_invalid_method', level="warning", guid=guid)
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')})
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_ab_peer_delete_unauthorized', level="warning", guid=guid)
        return JsonResponse({'error': 'Invalid token'}, status=401)
    profile, owner, rule = _get_profile_access(user, guid)
    if guid == _personal_guid(user):
        _ensure_personal_profile(user)
        owner = user
        rule = 3
    if not owner:
        _log_event(request, 'api_ab_peer_delete_denied', level="warning", username=user.username, guid=guid)
        return JsonResponse({'error': 'No access'}, status=403)
    if not _can_write_rule(rule):
        _log_event(request, 'api_ab_peer_delete_denied', level="warning", username=user.username, guid=guid, reason='read_only')
        return JsonResponse({'error': 'Read-only'}, status=403)
    postdata = _load_json(request)
    if not isinstance(postdata, list):
        _log_event(request, 'api_ab_peer_delete_failed', level="warning", username=user.username, guid=guid, reason='invalid_ids')
        return JsonResponse({'error': 'Invalid ids'}, status=400)
    RustDeskPeer.objects.filter(Q(uid=owner.id) & Q(profile_guid=guid) & Q(rid__in=postdata)).delete()
    _log_event(request, 'api_ab_peer_delete', username=user.username, guid=guid, count=len(postdata))
    return HttpResponse('')


def ab_tag_add(request, guid):
    if request.method == 'GET':
        _log_event(request, 'api_ab_tag_add_invalid_method', level="warning", guid=guid)
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')})
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_ab_tag_add_unauthorized', level="warning", guid=guid)
        return JsonResponse({'error': 'Invalid token'}, status=401)
    profile, owner, rule = _get_profile_access(user, guid)
    if guid == _personal_guid(user):
        _ensure_personal_profile(user)
        owner = user
        rule = 3
    if not owner:
        _log_event(request, 'api_ab_tag_add_denied', level="warning", username=user.username, guid=guid)
        return JsonResponse({'error': 'No access'}, status=403)
    if not _can_write_rule(rule):
        _log_event(request, 'api_ab_tag_add_denied', level="warning", username=user.username, guid=guid, reason='read_only')
        return JsonResponse({'error': 'Read-only'}, status=403)
    postdata = _load_json(request)
    name = postdata.get('name', '')
    color = postdata.get('color', '')
    if not name:
        _log_event(request, 'api_ab_tag_add_failed', level="warning", username=user.username, guid=guid, reason='missing_name')
        return JsonResponse({'error': 'Invalid tag'}, status=400)
    if not RustDeskTag.objects.filter(Q(uid=owner.id) & Q(tag_name=name) & Q(profile_guid=guid)).first():
        RustDeskTag(uid=owner.id, tag_name=name, tag_color=str(color), profile_guid=guid).save()
    _log_event(request, 'api_ab_tag_add', username=user.username, guid=guid, tag=name)
    return HttpResponse('')


def ab_tag_rename(request, guid):
    if request.method == 'GET':
        _log_event(request, 'api_ab_tag_rename_invalid_method', level="warning", guid=guid)
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')})
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_ab_tag_rename_unauthorized', level="warning", guid=guid)
        return JsonResponse({'error': 'Invalid token'}, status=401)
    profile, owner, rule = _get_profile_access(user, guid)
    if guid == _personal_guid(user):
        _ensure_personal_profile(user)
        owner = user
        rule = 3
    if not owner:
        _log_event(request, 'api_ab_tag_rename_denied', level="warning", username=user.username, guid=guid)
        return JsonResponse({'error': 'No access'}, status=403)
    if not _can_write_rule(rule):
        _log_event(request, 'api_ab_tag_rename_denied', level="warning", username=user.username, guid=guid, reason='read_only')
        return JsonResponse({'error': 'Read-only'}, status=403)
    postdata = _load_json(request)
    old = postdata.get('old', '')
    new = postdata.get('new', '')
    if not old or not new:
        _log_event(request, 'api_ab_tag_rename_failed', level="warning", username=user.username, guid=guid, reason='invalid_tag')
        return JsonResponse({'error': 'Invalid tag'}, status=400)
    RustDeskTag.objects.filter(Q(uid=owner.id) & Q(tag_name=old) & Q(profile_guid=guid)).update(tag_name=new)
    peers = RustDeskPeer.objects.filter(Q(uid=owner.id) & Q(profile_guid=guid))
    for p in peers:
        tags = [x for x in p.tags.split(',') if x]
        if old in tags:
            tags = [new if x == old else x for x in tags]
            p.tags = ','.join(tags)
            p.save()
    _log_event(request, 'api_ab_tag_rename', username=user.username, guid=guid, old=old, new=new)
    return HttpResponse('')


def ab_tag_update(request, guid):
    if request.method == 'GET':
        _log_event(request, 'api_ab_tag_update_invalid_method', level="warning", guid=guid)
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')})
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_ab_tag_update_unauthorized', level="warning", guid=guid)
        return JsonResponse({'error': 'Invalid token'}, status=401)
    profile, owner, rule = _get_profile_access(user, guid)
    if guid == _personal_guid(user):
        _ensure_personal_profile(user)
        owner = user
        rule = 3
    if not owner:
        _log_event(request, 'api_ab_tag_update_denied', level="warning", username=user.username, guid=guid)
        return JsonResponse({'error': 'No access'}, status=403)
    if not _can_write_rule(rule):
        _log_event(request, 'api_ab_tag_update_denied', level="warning", username=user.username, guid=guid, reason='read_only')
        return JsonResponse({'error': 'Read-only'}, status=403)
    postdata = _load_json(request)
    name = postdata.get('name', '')
    color = postdata.get('color', '')
    if not name:
        _log_event(request, 'api_ab_tag_update_failed', level="warning", username=user.username, guid=guid, reason='missing_name')
        return JsonResponse({'error': 'Invalid tag'}, status=400)
    RustDeskTag.objects.filter(Q(uid=owner.id) & Q(tag_name=name) & Q(profile_guid=guid)).update(tag_color=str(color))
    _log_event(request, 'api_ab_tag_update', username=user.username, guid=guid, tag=name)
    return HttpResponse('')


def ab_tag_delete(request, guid):
    if request.method == 'GET':
        _log_event(request, 'api_ab_tag_delete_invalid_method', level="warning", guid=guid)
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')})
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_ab_tag_delete_unauthorized', level="warning", guid=guid)
        return JsonResponse({'error': 'Invalid token'}, status=401)
    profile, owner, rule = _get_profile_access(user, guid)
    if guid == _personal_guid(user):
        _ensure_personal_profile(user)
        owner = user
        rule = 3
    if not owner:
        _log_event(request, 'api_ab_tag_delete_denied', level="warning", username=user.username, guid=guid)
        return JsonResponse({'error': 'No access'}, status=403)
    if not _can_write_rule(rule):
        _log_event(request, 'api_ab_tag_delete_denied', level="warning", username=user.username, guid=guid, reason='read_only')
        return JsonResponse({'error': 'Read-only'}, status=403)
    postdata = _load_json(request)
    if not isinstance(postdata, list):
        _log_event(request, 'api_ab_tag_delete_failed', level="warning", username=user.username, guid=guid, reason='invalid_tags')
        return JsonResponse({'error': 'Invalid tags'}, status=400)
    RustDeskTag.objects.filter(Q(uid=owner.id) & Q(profile_guid=guid) & Q(tag_name__in=postdata)).delete()
    peers = RustDeskPeer.objects.filter(Q(uid=owner.id) & Q(profile_guid=guid))
    for p in peers:
        tags = [x for x in p.tags.split(',') if x and x not in postdata]
        p.tags = ','.join(tags)
        p.save()
    _log_event(request, 'api_ab_tag_delete', username=user.username, guid=guid, count=len(postdata))
    return HttpResponse('')


def _audit_conn_active(request):
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_audit_conn_active_unauthorized', level="warning")
        return JsonResponse('', safe=False, status=401)
    peer_id = request.GET.get('id', '')
    session_id = request.GET.get('session_id', '')
    try:
        conn_type = int(request.GET.get('conn_type', 0))
    except Exception:
        conn_type = 0
    if not peer_id or not session_id:
        _log_event(request, 'api_audit_conn_active_failed', level="warning", reason='missing_id')
        return JsonResponse('', safe=False)
    session = AuditSession.objects.filter(Q(peer_id=peer_id) & Q(session_id=session_id)).first()
    if not session:
        session = AuditSession(
            guid=uuid.uuid4().hex,
            peer_id=peer_id,
            session_id=session_id,
            conn_type=conn_type,
        )
        session.save()
    else:
        if conn_type and session.conn_type != conn_type:
            session.conn_type = conn_type
            session.save(update_fields=['conn_type'])
    _log_event(request, 'api_audit_conn_active', level="debug", username=user.username, peer_id=peer_id, session_id=session_id, conn_type=conn_type)
    return JsonResponse(session.guid, safe=False)


def _audit_conn(request):
    postdata = _load_json(request)
    if not isinstance(postdata, dict):
        _log_event(request, 'api_audit_conn_invalid_payload', level="warning")
        return JsonResponse({'error': 'Invalid payload'}, status=400)
    action = postdata.get('action', '')
    conn_id = postdata.get('conn_id', '')
    peer_id = postdata.get('id', '')
    session_id = postdata.get('session_id', '')
    if action == 'new':
        conn_type = postdata.get('type', None)
        try:
            conn_type = int(conn_type) if conn_type is not None else None
        except Exception:
            conn_type = None
        ConnLog.objects.create(
            action=action,
            conn_id=conn_id,
            from_ip=postdata.get('ip', ''),
            from_id='',
            rid=peer_id,
            conn_start=timezone.now(),
            session_id=session_id,
            uuid=postdata.get('uuid', ''),
            conn_type=conn_type if conn_type is not None else None,
        )
        if peer_id and session_id:
            AuditSession.objects.get_or_create(
                peer_id=peer_id,
                session_id=session_id,
                defaults={'guid': uuid.uuid4().hex, 'conn_type': conn_type or 0},
            )
        _log_event(request, 'api_audit_conn_new', level="info", conn_id=conn_id, peer_id=peer_id, session_id=session_id, conn_type=conn_type)
    elif action == 'close':
        if conn_id:
            ConnLog.objects.filter(Q(conn_id=conn_id)).update(conn_end=timezone.now())
        _log_event(request, 'api_audit_conn_close', level="info", conn_id=conn_id, peer_id=peer_id, session_id=session_id)
    else:
        if conn_id and session_id:
            ConnLog.objects.filter(Q(conn_id=conn_id)).update(session_id=session_id)
        if conn_id and 'peer' in postdata:
            peer = postdata.get('peer', [])
            if isinstance(peer, (list, tuple)) and peer:
                ConnLog.objects.filter(Q(conn_id=conn_id)).update(from_id=str(peer[0]))
        if conn_id and 'type' in postdata:
            try:
                update_type = int(postdata.get('type'))
            except Exception:
                update_type = postdata.get('type')
            ConnLog.objects.filter(Q(conn_id=conn_id)).update(conn_type=update_type)
        _log_event(request, 'api_audit_conn_update', level="debug", conn_id=conn_id, peer_id=peer_id, session_id=session_id)
    return JsonResponse({'code': 1, 'data': 'ok'})


def _audit_file(request):
    postdata = _load_json(request)
    if not isinstance(postdata, dict):
        _log_event(request, 'api_audit_file_invalid_payload', level="warning")
        return JsonResponse({'error': 'Invalid payload'}, status=400)
    if 'is_file' not in postdata:
        return JsonResponse({'code': 1, 'data': 'ok'})
    info = postdata.get('info', '{}')
    try:
        info_obj = json.loads(info) if isinstance(info, str) else info
    except Exception as e:
        logger.warning('audit file info parse failed: %s', e)
        info_obj = {}
    files = info_obj.get('files', [])
    total_size = 0
    if files and isinstance(files, list):
        total_size = sum(int(f[1]) for f in files if isinstance(f, (list, tuple)) and len(f) > 1)
    filesize = convert_filesize(int(total_size)) if total_size else ''
    FileLog.objects.create(
        file=postdata.get('path', ''),
        user_id=postdata.get('peer_id', ''),
        user_ip=info_obj.get('ip', ''),
        remote_id=postdata.get('id', ''),
        filesize=filesize,
        direction=postdata.get('type', 0),
        logged_at=timezone.now(),
    )
    _log_event(request, 'api_audit_file', level="info", peer_id=postdata.get('peer_id', ''), remote_id=postdata.get('id', ''), direction=postdata.get('type', 0), filesize=filesize)
    return JsonResponse({'code': 1, 'data': 'ok'})


def _audit_alarm(request):
    postdata = _load_json(request)
    if not isinstance(postdata, dict):
        _log_event(request, 'api_audit_alarm_invalid_payload', level="warning")
        return JsonResponse({'error': 'Invalid payload'}, status=400)
    AlarmLog.objects.create(
        typ=postdata.get('typ', 0),
        info=postdata.get('info', ''),
    )
    _log_event(request, 'api_audit_alarm', level="warning", typ=postdata.get('typ', 0))
    return JsonResponse({'code': 1, 'data': 'ok'})


def audit(request):
    return _audit_conn(request)


def convert_filesize(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])


def _pagination(request, default=100):
    try:
        current = max(1, int(request.GET.get('current', 1)))
        page_size = max(1, min(500, int(request.GET.get('pageSize', default))))
    except Exception:
        current = 1
        page_size = default
    start = (current - 1) * page_size
    return current, page_size, start, start + page_size


def _paged_response(request, qs, serializer, default_page_size=100):
    current, page_size, start, end = _pagination(request, default_page_size)
    total = qs.count() if isinstance(qs, QuerySet) else len(qs)
    rows = qs[start:end]
    return JsonResponse({
        'total': total,
        'current': current,
        'pageSize': page_size,
        'data': [serializer(item) for item in rows],
    })


def _filter_text(qs, field, value):
    value = str(value or '').strip()
    if not value:
        return qs
    if '%' in value:
        return qs.filter(**{f'{field}__icontains': value.replace('%', '')})
    return qs.filter(**{field: value})


def _json_text(value):
    if value in (None, ''):
        return []
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return []


def _require_admin(request, event):
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, f'{event}_unauthorized', level="warning")
        return None, JsonResponse({'error': 'Invalid token'}, status=401)
    if not user.is_admin:
        _log_event(request, f'{event}_denied', level="warning", username=user.username)
        return user, JsonResponse({'error': 'Admin required'}, status=403)
    return user, None


def _device_guid(device):
    return str(device.pk)


def _user_guid(user):
    return str(user.pk)


def _serialize_user(u):
    return {
        'guid': _user_guid(u),
        'name': u.username,
        'username': u.username,
        'status': 1 if u.is_active else 0,
        'is_admin': True if u.is_admin else False,
        'email': u.email or '',
        'note': u.note or '',
        'group_name': u.group_name or '',
        'strategy_name': u.strategy_name or '',
        'tfa_enforced': bool(u.tfa_enforced),
        'login_verification_disabled': bool(u.login_verification_disabled),
    }


def _serialize_device(device):
    owner_name = device.owner.username if device.owner else device.owner_name
    return {
        'guid': _device_guid(device),
        'id': device.rid,
        'name': device.hostname,
        'device_name': device.hostname,
        'device_username': device.username,
        'user_name': owner_name or '',
        'group_name': device.owner.group_name if device.owner else '',
        'device_group_name': device.device_group_name or '',
        'strategy_name': device.strategy_name or '',
        'status': 1 if device.is_active else 0,
        'online': _is_online(device.update_time),
        'last_online': device.update_time.isoformat() if device.update_time else '',
        'platform': device.os,
        'version': device.version,
        'ip_address': device.ip_address,
        'note': device.note or '',
    }


def _serialize_device_group(group):
    return {
        'guid': str(group.guid),
        'name': group.name,
        'note': group.note or '',
        'allowed_incomings': _json_text(group.allowed_incomings),
        'strategy_name': group.strategy_name or '',
    }


def _serialize_strategy(strategy):
    return {
        'guid': str(strategy.guid),
        'name': strategy.name,
        'enabled': bool(strategy.enabled),
        'status': 1 if strategy.enabled else 0,
        'config_options': _json_text(strategy.config_options) if strategy.config_options else {},
        'updated_at': strategy.updated_at.isoformat() if strategy.updated_at else '',
    }


def _is_online(updated_at):
    return (timezone.now() - updated_at).total_seconds() <= 120 if updated_at else False


def _coerce_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ('1', 'true', 'yes', 'on')
    if value is None:
        return default
    return bool(value)


def users(request):
    if request.method == 'POST':
        admin_user, error = _require_admin(request, 'api_users_create')
        if error:
            return error
        data = _load_json(request)
        username = str(data.get('name') or data.get('username') or '').strip()
        password = str(data.get('password') or '').strip()
        if not username or not password:
            return JsonResponse({'error': 'name and password are required'}, status=400)
        if UserProfile.objects.filter(username=username).exists():
            return JsonResponse({'error': 'User already exists'}, status=409)
        user = UserProfile.objects.create_user(
            username=username,
            password=password,
            email=str(data.get('email') or ''),
            note=str(data.get('note') or ''),
            group_name=str(data.get('group_name') or ''),
        )
        _log_event(request, 'api_users_created', username=admin_user.username, target=username)
        return JsonResponse(_serialize_user(user))
    if request.method != 'GET':
        _log_event(request, 'api_users_invalid_method', level="warning")
        return JsonResponse({'error': _('错误的提交方式！')})
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_users_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    qs = UserProfile.objects.all().order_by('id')
    if not user.is_admin:
        qs = qs.filter(Q(id=user.id))
    qs = _filter_text(qs, 'username', request.GET.get('name'))
    qs = _filter_text(qs, 'group_name', request.GET.get('group_name'))
    status = request.GET.get('status', '')
    if status == '1':
        qs = qs.filter(Q(is_active=True))
    elif status == '0':
        qs = qs.filter(Q(is_active=False))
    _log_event(request, 'api_users', level="debug", username=user.username, total=qs.count())
    return _paged_response(request, qs, _serialize_user)


def users_invite(request):
    if request.method != 'POST':
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')}, status=405)
    admin_user, error = _require_admin(request, 'api_users_invite')
    if error:
        return error
    data = _load_json(request)
    username = str(data.get('name') or data.get('email') or '').strip()
    email = str(data.get('email') or '').strip()
    if not username or not email:
        return JsonResponse({'error': 'name and email are required'}, status=400)
    user, created = UserProfile.objects.get_or_create(username=username, defaults={
        'email': email,
        'note': str(data.get('note') or ''),
        'group_name': str(data.get('group_name') or ''),
        'is_active': True,
    })
    if created:
        user.set_unusable_password()
        user.save()
    _log_event(request, 'api_users_invited', username=admin_user.username, target=username)
    return JsonResponse(_serialize_user(user))


def _user_by_guid(guid):
    return UserProfile.objects.filter(pk=guid).first()


def user_status(request, guid, action):
    if request.method != 'POST':
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')}, status=405)
    admin_user, error = _require_admin(request, f'api_user_{action}')
    if error:
        return error
    target = _user_by_guid(guid)
    if not target:
        return JsonResponse({'error': 'User not found'}, status=404)
    target.is_active = action == 'enable'
    target.save(update_fields=['is_active'])
    if not target.is_active:
        RustDeskToken.objects.filter(uid=str(target.id)).delete()
    _log_event(request, f'api_user_{action}', username=admin_user.username, target=target.username)
    return JsonResponse(_serialize_user(target))


def user_delete(request, guid):
    if request.method != 'DELETE':
        return JsonResponse({'error': 'DELETE required'}, status=405)
    admin_user, error = _require_admin(request, 'api_user_delete')
    if error:
        return error
    target = _user_by_guid(guid)
    if not target:
        return JsonResponse({'error': 'User not found'}, status=404)
    if target.id == admin_user.id:
        return JsonResponse({'error': 'Cannot delete current user'}, status=400)
    username = target.username
    RustDeskToken.objects.filter(uid=str(target.id)).delete()
    target.delete()
    _log_event(request, 'api_user_deleted', username=admin_user.username, target=username)
    return JsonResponse({'result': 'OK'})


def users_tfa_enforce(request):
    if request.method != 'PUT':
        return JsonResponse({'error': 'PUT required'}, status=405)
    admin_user, error = _require_admin(request, 'api_users_tfa_enforce')
    if error:
        return error
    data = _load_json(request)
    guids = data.get('user_guids') or []
    enforce = bool(data.get('enforce'))
    updated = UserProfile.objects.filter(pk__in=guids).update(tfa_enforced=enforce)
    _log_event(request, 'api_users_tfa_enforce', username=admin_user.username, updated=updated, enforce=enforce)
    return JsonResponse({'result': 'OK', 'updated': updated})


def users_disable_login_verification(request):
    if request.method != 'PUT':
        return JsonResponse({'error': 'PUT required'}, status=405)
    admin_user, error = _require_admin(request, 'api_users_disable_login_verification')
    if error:
        return error
    data = _load_json(request)
    guids = data.get('user_guids') or []
    updated = UserProfile.objects.filter(pk__in=guids).update(login_verification_disabled=True)
    _log_event(request, 'api_users_disable_login_verification', username=admin_user.username, updated=updated, typ=data.get('type'))
    return JsonResponse({'result': 'OK', 'updated': updated})


def users_force_logout(request):
    if request.method != 'POST':
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')}, status=405)
    admin_user, error = _require_admin(request, 'api_users_force_logout')
    if error:
        return error
    data = _load_json(request)
    guids = [str(x) for x in (data.get('user_guids') or [])]
    deleted = RustDeskToken.objects.filter(uid__in=guids).delete()[0]
    _log_event(request, 'api_users_force_logout', username=admin_user.username, deleted=deleted)
    return JsonResponse({'result': 'OK', 'deleted': deleted})


def devices(request):
    if request.method != 'GET':
        return JsonResponse({'error': _('错误的提交方式！')}, status=405)
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_devices_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    qs = RustDesDevice.objects.select_related('owner').all().order_by('rid')
    if not user.is_admin:
        qs = qs.filter(Q(owner=user))
    qs = _filter_text(qs, 'rid', request.GET.get('id'))
    qs = _filter_text(qs, 'hostname', request.GET.get('device_name'))
    qs = _filter_text(qs, 'username', request.GET.get('device_username'))
    qs = _filter_text(qs, 'device_group_name', request.GET.get('device_group_name'))
    user_name = request.GET.get('user_name')
    if user_name:
        qs = _filter_text(qs, 'owner_name', user_name)
    group_name = request.GET.get('group_name')
    if group_name:
        qs = qs.filter(owner__group_name=group_name.replace('%', '') if '%' in group_name else group_name)
    return _paged_response(request, qs, _serialize_device)


def _device_by_guid(guid):
    return RustDesDevice.objects.filter(pk=guid).first()


def device_status(request, guid, action):
    if request.method != 'POST':
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')}, status=405)
    admin_user, error = _require_admin(request, f'api_device_{action}')
    if error:
        return error
    device = _device_by_guid(guid)
    if not device:
        return JsonResponse({'error': 'Device not found'}, status=404)
    device.is_active = action == 'enable'
    device.save(update_fields=['is_active'])
    _log_event(request, f'api_device_{action}', username=admin_user.username, rid=device.rid)
    return JsonResponse(_serialize_device(device))


def device_delete(request, guid):
    if request.method != 'DELETE':
        return JsonResponse({'error': 'DELETE required'}, status=405)
    admin_user, error = _require_admin(request, 'api_device_delete')
    if error:
        return error
    device = _device_by_guid(guid)
    if not device:
        return JsonResponse({'error': 'Device not found'}, status=404)
    rid = device.rid
    device.delete()
    _log_event(request, 'api_device_deleted', username=admin_user.username, rid=rid)
    return JsonResponse({'result': 'OK'})


def device_assign(request, guid):
    if request.method != 'POST':
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')}, status=405)
    admin_user, error = _require_admin(request, 'api_device_assign')
    if error:
        return error
    device = _device_by_guid(guid)
    if not device:
        return JsonResponse({'error': 'Device not found'}, status=404)
    data = _load_json(request)
    typ = str(data.get('type') or '')
    value = str(data.get('value') or '')
    if typ == 'user_name':
        owner = UserProfile.objects.filter(username=value).first()
        if not owner:
            return JsonResponse({'error': 'User not found'}, status=404)
        device.owner = owner
        device.owner_name = owner.username
    elif typ == 'device_group_name':
        if not value:
            device.device_group_name = ''
        else:
            DeviceGroup.objects.get_or_create(name=value)
            device.device_group_name = value
    elif typ == 'strategy_name':
        device.strategy_name = value
    elif typ == 'note':
        device.note = value
    elif typ == 'device_username':
        device.username = value
    elif typ == 'device_name':
        device.hostname = value
    elif typ == 'ab':
        parts = value.split(',')
        device.address_book_name = parts[0] if len(parts) > 0 else ''
        device.address_book_tag = parts[1] if len(parts) > 1 else ''
        device.address_book_alias = parts[2] if len(parts) > 2 else ''
        device.address_book_password = parts[3] if len(parts) > 3 else ''
        device.address_book_note = parts[4] if len(parts) > 4 else ''
    else:
        return JsonResponse({'error': 'Invalid assign type'}, status=400)
    device.save()
    _log_event(request, 'api_device_assigned', username=admin_user.username, rid=device.rid, typ=typ)
    return JsonResponse(_serialize_device(device))


def peers(request):
    if request.method != 'GET':
        _log_event(request, 'api_peers_invalid_method', level="warning")
        return JsonResponse({'error': _('错误的提交方式！')})
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_peers_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    try:
        current = int(request.GET.get('current', 1))
        page_size = int(request.GET.get('pageSize', 100))
    except Exception:
        current = 1
        page_size = 100
    if user.is_admin:
        device_qs = RustDesDevice.objects.all().select_related('owner').order_by('rid')
        peer_qs = RustDeskPeer.objects.all()
    else:
        peer_qs = RustDeskPeer.objects.filter(Q(uid=user.id))
        peer_ids = [x.rid for x in peer_qs]
        device_qs = RustDesDevice.objects.filter(Q(owner=user) | Q(rid__in=peer_ids)).select_related('owner')
        device_qs = device_qs.order_by('rid')
    devices = {x.rid: x for x in device_qs}
    peers_by_rid = {x.rid: x for x in peer_qs}
    status_filter = request.GET.get('status', '')
    device_ids = list(devices.keys())
    if status_filter in ('0', '1'):
        target = 1 if status_filter == '1' else 0
        device_ids = [
            rid for rid in device_ids
            if (devices.get(rid) and _is_online(devices[rid].update_time)) == (target == 1)
        ]
    total = len(device_ids)
    start = (current - 1) * page_size
    end = start + page_size
    data = []
    for rid in device_ids[start:end]:
        device = devices.get(rid)
        peer = peers_by_rid.get(rid)
        username = device.username if device and device.username else (peer.username if peer else '')
        owner = ''
        if device and device.owner:
            owner = device.owner.username
        elif device and device.owner_name:
            owner = device.owner_name
        elif peer:
            u = UserProfile.objects.filter(Q(id=peer.uid)).first()
            if u:
                owner = u.username
        status = 0
        if device and _is_online(device.update_time):
            status = 1
        data.append({
            'id': rid,
            'info': {
                'username': username,
                'os': device.os if device else '',
                'device_name': device.hostname if device else '',
            },
            'status': status,
            'user': owner,
            'user_name': owner,
            'device_group_name': device.device_group_name if device else '',
            'note': device.note if device else '',
        })
    _log_event(request, 'api_peers', level="debug", username=user.username, total=total, page=current, page_size=page_size)
    return JsonResponse({'total': total, 'data': data})


def device_group_accessible(request):
    if request.method != 'GET':
        _log_event(request, 'api_device_group_accessible_invalid_method', level="warning")
        return JsonResponse({'error': _('错误的提交方式！')})
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_device_group_accessible_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    if user.is_admin:
        groups = list(DeviceGroup.objects.all().order_by('name'))
    else:
        peer_ids = list(RustDeskPeer.objects.filter(Q(uid=user.id)).values_list('rid', flat=True))
        device_qs = RustDesDevice.objects.filter(Q(owner=user) | Q(rid__in=peer_ids))
        names = sorted({d.device_group_name for d in device_qs if d.device_group_name})
        groups = [DeviceGroup.objects.filter(name=name).first() or DeviceGroup(name=name) for name in names]
    data = [_serialize_device_group(group) for group in groups]
    _log_event(request, 'api_device_group_accessible', level="debug", username=user.username, total=len(data))
    return JsonResponse({'total': len(data), 'data': data})


def device_groups(request):
    if request.method == 'POST':
        admin_user, error = _require_admin(request, 'api_device_groups_create')
        if error:
            return error
        data = _load_json(request)
        name = str(data.get('name') or '').strip()
        if not name:
            return JsonResponse({'error': 'name is required'}, status=400)
        group, created = DeviceGroup.objects.get_or_create(name=name)
        group.note = str(data.get('note') or group.note or '')
        if 'allowed_incomings' in data:
            group.allowed_incomings = json.dumps(data.get('allowed_incomings') or [], ensure_ascii=False)
        if 'strategy_name' in data:
            group.strategy_name = str(data.get('strategy_name') or '')
        group.save()
        _log_event(request, 'api_device_groups_created', username=admin_user.username, target=name, created=created)
        return JsonResponse(_serialize_device_group(group))
    if request.method != 'GET':
        return JsonResponse({'error': _('错误的提交方式！')}, status=405)
    admin_user, error = _require_admin(request, 'api_device_groups')
    if error:
        return error
    qs = DeviceGroup.objects.all().order_by('name')
    qs = _filter_text(qs, 'name', request.GET.get('name'))
    return _paged_response(request, qs, _serialize_device_group)


def _device_group_by_guid(guid):
    return DeviceGroup.objects.filter(guid=guid).first()


def device_group_detail(request, guid):
    admin_user, error = _require_admin(request, 'api_device_group_detail')
    if error:
        return error
    group = _device_group_by_guid(guid)
    if not group:
        return JsonResponse({'error': 'Device group not found'}, status=404)
    if request.method == 'PATCH':
        data = _load_json(request)
        old_name = group.name
        if 'name' in data:
            new_name = str(data.get('name') or '').strip()
            if not new_name:
                return JsonResponse({'error': 'name is required'}, status=400)
            if DeviceGroup.objects.filter(name=new_name).exclude(guid=group.guid).exists():
                return JsonResponse({'error': 'Device group already exists'}, status=409)
            group.name = new_name
        if 'note' in data:
            group.note = str(data.get('note') or '')
        if 'allowed_incomings' in data:
            group.allowed_incomings = json.dumps(data.get('allowed_incomings') or [], ensure_ascii=False)
        if 'strategy_name' in data:
            group.strategy_name = str(data.get('strategy_name') or '')
        try:
            group.save()
        except IntegrityError:
            return JsonResponse({'error': 'Device group already exists'}, status=409)
        if old_name != group.name:
            RustDesDevice.objects.filter(device_group_name=old_name).update(device_group_name=group.name)
        return JsonResponse(_serialize_device_group(group))
    if request.method == 'POST':
        ids = _load_json(request)
        if not isinstance(ids, list):
            return JsonResponse({'error': 'Device id list required'}, status=400)
        updated = RustDesDevice.objects.filter(rid__in=[str(x) for x in ids]).update(device_group_name=group.name)
        _log_event(request, 'api_device_group_add_devices', username=admin_user.username, target=group.name, updated=updated)
        return JsonResponse({'result': 'OK', 'updated': updated})
    if request.method == 'DELETE':
        name = group.name
        RustDesDevice.objects.filter(device_group_name=name).update(device_group_name='')
        group.delete()
        _log_event(request, 'api_device_group_deleted', username=admin_user.username, target=name)
        return JsonResponse({'result': 'OK'})
    return JsonResponse({'error': 'POST, PATCH or DELETE required'}, status=405)


def device_group_remove_devices(request, guid):
    if request.method != 'DELETE':
        return JsonResponse({'error': 'DELETE required'}, status=405)
    admin_user, error = _require_admin(request, 'api_device_group_remove_devices')
    if error:
        return error
    group = _device_group_by_guid(guid)
    if not group:
        return JsonResponse({'error': 'Device group not found'}, status=404)
    ids = _load_json(request)
    if not isinstance(ids, list):
        return JsonResponse({'error': 'Device id list required'}, status=400)
    updated = RustDesDevice.objects.filter(rid__in=[str(x) for x in ids], device_group_name=group.name).update(device_group_name='')
    _log_event(request, 'api_device_group_remove_devices', username=admin_user.username, target=group.name, updated=updated)
    return JsonResponse({'result': 'OK', 'updated': updated})


def strategies(request):
    if request.method != 'GET':
        return JsonResponse({'error': _('错误的提交方式！')}, status=405)
    admin_user, error = _require_admin(request, 'api_strategies')
    if error:
        return error
    qs = StrategyProfile.objects.all().order_by('name')
    return JsonResponse([_serialize_strategy(strategy) for strategy in qs], safe=False)


def strategy_detail(request, guid):
    admin_user, error = _require_admin(request, 'api_strategy_detail')
    if error:
        return error
    strategy = StrategyProfile.objects.filter(guid=guid).first()
    if not strategy:
        return JsonResponse({'error': 'Strategy not found'}, status=404)
    if request.method != 'GET':
        return JsonResponse({'error': _('错误的提交方式！')}, status=405)
    return JsonResponse(_serialize_strategy(strategy))


def strategy_status(request, guid):
    if request.method != 'PUT':
        return JsonResponse({'error': 'PUT required'}, status=405)
    admin_user, error = _require_admin(request, 'api_strategy_status')
    if error:
        return error
    strategy = StrategyProfile.objects.filter(guid=guid).first()
    if not strategy:
        return JsonResponse({'error': 'Strategy not found'}, status=404)
    data = _load_json(request)
    strategy.enabled = _coerce_bool(data if isinstance(data, bool) else data.get('enabled', True), True)
    strategy.save(update_fields=['enabled', 'updated_at'])
    _log_event(request, 'api_strategy_status', username=admin_user.username, target=strategy.name, enabled=strategy.enabled)
    return JsonResponse(_serialize_strategy(strategy))


def strategy_assign(request):
    if request.method != 'POST':
        return JsonResponse({'error': _('请求方式错误！请使用POST方式。')}, status=405)
    admin_user, error = _require_admin(request, 'api_strategy_assign')
    if error:
        return error
    data = _load_json(request)
    strategy_name = ''
    strategy_guid = data.get('strategy')
    if strategy_guid:
        strategy = StrategyProfile.objects.filter(guid=strategy_guid).first()
        if not strategy:
            return JsonResponse({'error': 'Strategy not found'}, status=404)
        strategy_name = strategy.name
    peer_guids = [str(x) for x in data.get('peers') or []]
    user_guids = [str(x) for x in data.get('users') or []]
    group_guids = [str(x) for x in data.get('groups') or []]
    devices_updated = RustDesDevice.objects.filter(pk__in=peer_guids).update(strategy_name=strategy_name)
    users_updated = UserProfile.objects.filter(pk__in=user_guids).update(strategy_name=strategy_name)
    groups = DeviceGroup.objects.filter(guid__in=group_guids)
    group_names = list(groups.values_list('name', flat=True))
    groups_updated = groups.update(strategy_name=strategy_name)
    if group_names:
        RustDesDevice.objects.filter(device_group_name__in=group_names).update(strategy_name=strategy_name)
    _log_event(
        request,
        'api_strategy_assign',
        username=admin_user.username,
        strategy=strategy_name,
        devices=devices_updated,
        users=users_updated,
        groups=groups_updated,
    )
    return JsonResponse({'result': 'OK', 'devices': devices_updated, 'users': users_updated, 'groups': groups_updated})
