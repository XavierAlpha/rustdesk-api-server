# cython:language_level=3
from django.http import JsonResponse, HttpResponse, HttpResponseRedirect
import json
import time
import datetime
import logging
import math
import os
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
    AddressBookProfile,
    AddressBookShare,
    AddressBookRule,
    AddressBookRuleAudit,
    AuditSession,
    AlarmLog,
)
from django.contrib.auth.models import Group
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from .views_front import *
from django.utils.translation import gettext as _
from django.conf import settings

logger = logging.getLogger(__name__)
EFFECTIVE_SECONDS = 7200


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
    if auth.strip():
        return auth.strip()
    token = request.GET.get('access_token') or request.GET.get('token') or request.GET.get('auth_token')
    if token:
        return str(token).strip()
    if request.method in ('POST', 'PUT', 'PATCH'):
        token = request.POST.get('access_token') or request.POST.get('token') or request.POST.get('auth_token')
        if token:
            return str(token).strip()
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
    return token, user


def _token_expired(token):
    now = timezone.now()
    expires_at = token.expires_at
    if not expires_at and token.create_time:
        expires_at = token.create_time + datetime.timedelta(seconds=EFFECTIVE_SECONDS)
    if expires_at and expires_at < now:
        return True
    return False

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


def _personal_guid(user):
    return f'personal-{user.id}'

def _personal_profile_name():
    lang = str(getattr(settings, "LANGUAGE_CODE", "")).lower()
    return "我的地址簿" if lang.startswith("zh") else "My address book"

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


def _next_id(model_cls):
    last = model_cls.objects.order_by('-id').first()
    return (last.id + 1) if last and last.id is not None else 1


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

    expires_at = timezone.now() + datetime.timedelta(seconds=EFFECTIVE_SECONDS)
    token = RustDeskToken.objects.filter(Q(uid=user.id) & Q(username=user.username) & Q(rid=user.rid)).first()
    if token and _token_expired(token):
        token.delete()
        token = None
    if not token:
        token = RustDeskToken(
            username=user.username,
            uid=user.id,
            uuid=user.uuid,
            rid=user.rid,
            access_token=getStrMd5(str(time.time()) + salt)
        )
    token.expires_at = expires_at
    token.save()

    device = RustDesDevice.objects.filter(Q(rid=rid) & Q(uuid=uuid)).first()
    if device and not user.is_admin and device.owner_id and device.owner_id != user.id:
        _log_event(request, 'api_login_denied', level="warning", username=username, reason='device_owner_mismatch', rid=rid)
        return JsonResponse({'error': 'Permission denied'}, status=403)
    if device:
        if device.owner_id is None or device.owner_id == user.id or user.is_admin:
            device.owner = user
            device.owner_name = user.username
        device.save()

    if rid:
        personal_guid = _personal_guid(user)
        peer = RustDeskPeer.objects.filter(Q(uid=user.id) & Q(rid=rid) & Q(profile_guid=personal_guid)).first()
        if not peer:
            legacy_peer = RustDeskPeer.objects.filter(Q(uid=user.id) & Q(rid=rid) & Q(profile_guid='')).first()
            if legacy_peer:
                legacy_peer.profile_guid = personal_guid
                legacy_peer.save()
            elif device:
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

    result['access_token'] = token.access_token
    result['type'] = 'access_token'
    result['user'] = {
        'name': user.username,
        'status': 1 if user.is_active else 0,
        'is_admin': True if user.is_admin else False,
        'email': user.email or '',
        'note': user.note or '',
    }
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
        tags_qs = RustDeskTag.objects.filter(Q(uid=user.id) & Q(profile_guid__in=[guid, '']))
        if tags_qs.exists() and not RustDeskTag.objects.filter(Q(uid=user.id) & Q(profile_guid=guid)).exists():
            tags_qs.update(profile_guid=guid)
        tags = RustDeskTag.objects.filter(Q(uid=user.id) & Q(profile_guid=guid))
        tag_names = [str(x.tag_name) for x in tags]
        tag_colors = {str(x.tag_name): int(x.tag_color) for x in tags if x.tag_color != ''}

        peers_qs = RustDeskPeer.objects.filter(Q(uid=user.id) & Q(profile_guid__in=[guid, '']))
        if peers_qs.exists() and not RustDeskPeer.objects.filter(Q(uid=user.id) & Q(profile_guid=guid)).exists():
            peers_qs.update(profile_guid=guid)
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

        result['updated_at'] = datetime.datetime.now()
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
            RustDeskTag.objects.filter(Q(uid=user.id) & Q(profile_guid__in=[guid, ''])).delete()
            RustDeskPeer.objects.filter(Q(uid=user.id) & Q(profile_guid__in=[guid, ''])).delete()
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


def ab_get(request):
    # 兼容 x86-sciter 版客户端，此版客户端通过访问 "POST /api/ab/get" 来获取地址簿
    _log_event(request, 'api_ab_get_compat', level="debug")
    request.method = 'GET'
    return ab(request)


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
        if profile:
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
    return JsonResponse([], safe=False)


def oidc_auth(request):
    _log_event(request, 'api_oidc_auth_unsupported', level="warning")
    return JsonResponse({'error': 'OIDC not supported'})


def oidc_auth_query(request):
    _log_event(request, 'api_oidc_auth_query_unsupported', level="warning")
    return JsonResponse({'error': 'OIDC not supported'})


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
    if name in ("My address book", "Legacy address book", "我的地址簿", "旧版地址簿"):
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
        rule = 3
        if RustDeskPeer.objects.filter(Q(uid=user.id) & Q(profile_guid='')).exists() and not RustDeskPeer.objects.filter(Q(uid=user.id) & Q(profile_guid=guid)).exists():
            RustDeskPeer.objects.filter(Q(uid=user.id) & Q(profile_guid='')).update(profile_guid=guid)
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
        if RustDeskTag.objects.filter(Q(uid=user.id) & Q(profile_guid='')).exists() and not RustDeskTag.objects.filter(Q(uid=user.id) & Q(profile_guid=guid)).exists():
            RustDeskTag.objects.filter(Q(uid=user.id) & Q(profile_guid='')).update(profile_guid=guid)
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
            id=_next_id(ConnLog),
            action=action,
            conn_id=conn_id,
            from_ip=postdata.get('ip', ''),
            from_id='',
            rid=peer_id,
            conn_start=datetime.datetime.now(),
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
            ConnLog.objects.filter(Q(conn_id=conn_id)).update(conn_end=datetime.datetime.now())
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
        id=_next_id(FileLog),
        file=postdata.get('path', ''),
        user_id=postdata.get('peer_id', ''),
        user_ip=info_obj.get('ip', ''),
        remote_id=postdata.get('id', ''),
        filesize=filesize,
        direction=postdata.get('type', 0),
        logged_at=datetime.datetime.now(),
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


def users(request):
    if request.method != 'GET':
        _log_event(request, 'api_users_invalid_method', level="warning")
        return JsonResponse({'error': _('错误的提交方式！')})
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, 'api_users_unauthorized', level="warning")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    try:
        current = int(request.GET.get('current', 1))
        page_size = int(request.GET.get('pageSize', 100))
    except Exception:
        current = 1
        page_size = 100
    qs = UserProfile.objects.all().order_by('id')
    if not user.is_admin:
        qs = qs.filter(Q(id=user.id))
    status = request.GET.get('status', '')
    if status == '1':
        qs = qs.filter(Q(is_active=True))
    elif status == '0':
        qs = qs.filter(Q(is_active=False))
    total = qs.count()
    start = (current - 1) * page_size
    end = start + page_size
    data = []
    for u in qs[start:end]:
        data.append({
            'name': u.username,
            'status': 1 if u.is_active else 0,
            'is_admin': True if u.is_admin else False,
            'email': u.email or '',
            'note': u.note or '',
        })
    _log_event(request, 'api_users', level="debug", username=user.username, total=total, page=current, page_size=page_size)
    return JsonResponse({'total': total, 'data': data})


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
    now = datetime.datetime.now()
    status_filter = request.GET.get('status', '')
    device_ids = list(devices.keys())
    if status_filter in ('0', '1'):
        target = 1 if status_filter == '1' else 0
        device_ids = [
            rid for rid in device_ids
            if (devices.get(rid) and (now - devices[rid].update_time).seconds <= 120) == (target == 1)
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
        if device and (now - device.update_time).seconds <= 120:
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
        device_qs = RustDesDevice.objects.all()
    else:
        peer_ids = list(RustDeskPeer.objects.filter(Q(uid=user.id)).values_list('rid', flat=True))
        device_qs = RustDesDevice.objects.filter(Q(owner=user) | Q(rid__in=peer_ids))
    groups = sorted({d.device_group_name for d in device_qs if d.device_group_name})
    data = [{'name': g} for g in groups]
    _log_event(request, 'api_device_group_accessible', level="debug", username=user.username, total=len(data))
    return JsonResponse({'total': len(data), 'data': data})
