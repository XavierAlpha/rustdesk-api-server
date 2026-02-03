# cython:language_level=3
from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.contrib.auth.hashers import make_password
from django.http import JsonResponse
from django.db.models import Q
from django.contrib.auth.decorators import login_required
from django.contrib import auth, messages
from api.models import (
    RustDeskPeer,
    RustDesDevice,
    UserProfile,
    RustDeskTag,
    ShareLink,
    ConnLog,
    FileLog,
    AddressBookProfile,
    AddressBookShare,
    AddressBookRule,
    AddressBookRuleAudit,
)
from django.forms.models import model_to_dict
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.conf import settings
from django.contrib.auth.models import Group

from itertools import chain
from django.db.models.fields import DateTimeField, DateField, CharField, TextField
import datetime
from django.db.models import Model
import json
import time
import hashlib
import sys
import logging
import uuid

from io import BytesIO, StringIO
from urllib.parse import urlencode
import csv
import xlwt
from django.utils.translation import gettext as _

salt = 'xiaomo'
logger = logging.getLogger(__name__)


def getStrMd5(s):
    if not isinstance(s, (str,)):
        s = str(s)

    myHash = hashlib.md5()
    myHash.update(s.encode())

    return myHash.hexdigest()


def _client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


def _log_event(request, event, level="info", **extra):
    user = getattr(request, 'user', None)
    username = user.username if user and getattr(user, 'is_authenticated', False) else 'anonymous'
    payload = {
        'event': event,
        'user': username,
        'ip': _client_ip(request),
        'path': getattr(request, 'path', ''),
        'method': getattr(request, 'method', ''),
    }
    payload.update({k: v for k, v in extra.items() if v is not None})
    details = json.dumps(payload, ensure_ascii=False)
    log_fn = getattr(logger, level, logger.info)
    log_fn("event=%s details=%s", event, details)


def model_to_dict2(instance, fields=None, exclude=None, replace=None, default=None):
    """
    :params instance: 模型对象，不能是queryset数据集
    :params fields: 指定要展示的字段数据，('字段1','字段2')
    :params exclude: 指定排除掉的字段数据,('字段1','字段2')
    :params replace: 将字段名字修改成需要的名字，{'数据库字段名':'前端展示名'}
    :params default: 新增不存在的字段数据，{'字段':'数据'}
    """
    # 对传递进来的模型对象校验
    if not isinstance(instance, Model):
        raise Exception(_('model_to_dict接收的参数必须是模型对象'))
    # 对替换数据库字段名字校验
    if replace and type(replace) == dict:   # noqa
        for replace_field in replace.values():
            if hasattr(instance, replace_field):
                raise Exception(_(f'model_to_dict,要替换成{replace_field}字段已经存在了'))
    # 对要新增的默认值进行校验
    if default and type(default) == dict:   # noqa
        for default_key in default.keys():
            if hasattr(instance, default_key):
                raise Exception(_(f'model_to_dict,要新增默认值，但字段{default_key}已经存在了'))  # noqa
    opts = instance._meta
    data = {}
    for f in chain(opts.concrete_fields, opts.private_fields, opts.many_to_many):
        # 源码下：这块代码会将时间字段剔除掉，我加上一层判断，让其不再剔除时间字段
        if not getattr(f, 'editable', False):
            if type(f) == DateField or type(f) == DateTimeField:   # noqa
                pass
            else:
                continue
        # 如果fields参数传递了，要进行判断
        if fields is not None and f.name not in fields:
            continue
        # 如果exclude 传递了，要进行判断
        if exclude and f.name in exclude:
            continue

        key = f.name
        # 获取字段对应的数据
        if type(f) == DateTimeField:   # noqa
            # 字段类型是，DateTimeFiled 使用自己的方式操作
            value = getattr(instance, key)
            value = datetime.datetime.strftime(value, '%Y-%m-%d %H:%M') if value else ''
        elif type(f) == DateField:   # noqa
            # 字段类型是，DateFiled 使用自己的方式操作
            value = getattr(instance, key)
            value = datetime.datetime.strftime(value, '%Y-%m-%d') if value else ''
        elif type(f) == CharField or type(f) == TextField:   # noqa
            # 字符串数据是否可以进行序列化，转成python结构数据
            value = getattr(instance, key)
            try:
                value = json.loads(value)
            except Exception as _:  # noqa
                value = value
        else:  # 其他类型的字段
            # value = getattr(instance, key)
            key = f.name
            value = f.value_from_object(instance)
            # data[f.name] = f.value_from_object(instance)
        # 1、替换字段名字
        if replace and key in replace.keys():
            key = replace.get(key)
        data[key] = value
    # 2、新增默认的字段数据
    if default:
        data.update(default)
    return data


DEVICE_DEFAULTS = {
    'rid': '',
    'alias': '',
    'device_group_name': '',
    'note': '',
    'version': '',
    'username': '',
    'hostname': '',
    'platform': '',
    'os': '',
    'cpu': '',
    'memory': '',
    'ip_address': '',
    'create_time': '',
    'update_time': '',
    'status': '',
    'owner_name': '',
    'rust_user': '',
    'strategy_name': '',
    'has_rhash': '',
}


def _normalize_device_item(item):
    for key, value in DEVICE_DEFAULTS.items():
        if key not in item:
            item[key] = value
    return item


def index(request):
    logger.debug('index args: %s', sys.argv)
    if request.user and getattr(request.user, 'is_authenticated', False):
        _log_event(request, 'front_redirect_home', level="debug")
        return HttpResponseRedirect('/api/home')
    _log_event(request, 'front_redirect_login', level="debug")
    return HttpResponseRedirect('/api/user_action?action=login')


def user_action(request):
    action = request.GET.get('action', '')
    if action == 'login':
        return user_login(request)
    elif action == 'register':
        return user_register(request)
    elif action == 'logout':
        return user_logout(request)
    else:
        return


def user_login(request):
    if request.method == 'GET':
        _log_event(request, 'front_login_view', level="debug")
        return render(request, 'login.html')

    username = request.POST.get('account', '').strip()
    password = request.POST.get('password', '')
    if not username or not password:
        return JsonResponse({'code': 0, 'msg': _('出了点问题，未获取用户名或密码。')})

    user = auth.authenticate(username=username, password=password)
    if not user:
        candidate = UserProfile.objects.filter(Q(username__iexact=username)).first()
        if candidate and candidate.check_password(password):
            candidate.backend = 'django.contrib.auth.backends.ModelBackend'
            user = candidate
        else:
            reason = 'password_mismatch' if candidate else 'user_not_found'
            _log_event(request, 'front_login_failed', level="warning", username=username, reason=reason)
            return JsonResponse({'code': 0, 'msg': _('帐号或密码错误！')})
    if user and not user.is_active:
        _log_event(request, 'front_login_denied', level="warning", username=username, reason='inactive')
        return JsonResponse({'code': 0, 'msg': _('帐号未激活，请联系管理员。')})
    if user:
        auth.login(request, user)
        _log_event(request, 'front_login_success', username=username)
        return JsonResponse({'code': 1, 'url': '/api/home'})
    return JsonResponse({'code': 0, 'msg': _('帐号或密码错误！')})


def user_register(request):
    info = ''
    if request.method == 'GET':
        _log_event(request, 'front_register_view', level="debug")
        return render(request, 'reg.html')
    ALLOW_REGISTRATION = settings.ALLOW_REGISTRATION
    result = {
        'code': 0,
        'msg': ''
    }
    if not ALLOW_REGISTRATION:
        result['msg'] = _('当前未开放注册，请联系管理员！')
        _log_event(request, 'front_register_denied', level="warning", reason='registration_disabled')
        return JsonResponse(result)

    username = request.POST.get('user', '').strip()
    password1 = request.POST.get('pwd', '')

    if len(username) <= 3:
        info = _('用户名不得小于3位')
        result['msg'] = info
        _log_event(request, 'front_register_failed', level="warning", username=username, reason='username_too_short')
        return JsonResponse(result)

    if len(password1) < 8 or len(password1) > 20:
        info = _('密码长度不符合要求, 应在8~20位。')
        result['msg'] = info
        _log_event(request, 'front_register_failed', level="warning", username=username, reason='password_length')
        return JsonResponse(result)

    user = UserProfile.objects.filter(Q(username=username)).first()
    if user:
        info = _('用户名已存在。')
        result['msg'] = info
        _log_event(request, 'front_register_failed', level="warning", username=username, reason='username_exists')
        return JsonResponse(result)
    user = UserProfile(
        username=username,
        password=make_password(password1),
        rid='',
        uuid='',
        rtype='',
        deviceInfo='',
        is_admin=True if UserProfile.objects.count() == 0 else False,
        is_superuser=True if UserProfile.objects.count() == 0 else False,
        is_active=True
    )
    user.save()
    result['msg'] = info
    result['code'] = 1
    _log_event(request, 'front_register_success', username=username)
    return JsonResponse(result)


@login_required(login_url='/api/user_action?action=login')
def user_logout(request):
    # info=''
    auth.logout(request)
    _log_event(request, 'front_logout')
    return HttpResponseRedirect('/api/user_action?action=login')


def get_single_info(uid):
    peers = RustDeskPeer.objects.filter(Q(uid=uid))
    rids = [x.rid for x in peers]
    peers = {x.rid: model_to_dict(x) for x in peers}
    # print(peers)
    devices = RustDesDevice.objects.filter(rid__in=rids)
    devices = {x.rid: x for x in devices}
    now = datetime.datetime.now()
    for rid, device in devices.items():
        peers[rid]['create_time'] = device.create_time.strftime('%Y-%m-%d')
        peers[rid]['update_time'] = device.update_time.strftime('%Y-%m-%d %H:%M')
        peers[rid]['version'] = device.version
        peers[rid]['memory'] = device.memory
        peers[rid]['cpu'] = device.cpu
        peers[rid]['os'] = device.os
        peers[rid]['device_group_name'] = device.device_group_name or peers[rid].get('device_group_name', '')
        peers[rid]['note'] = device.note or peers[rid].get('note', '')
        peers[rid]['strategy_name'] = device.strategy_name or peers[rid].get('strategy_name', '')
        peers[rid]['status'] = _('在线') if (now - device.update_time).seconds <= 120 else _('离线')

    for rid in peers.keys():
        rhash_value = peers[rid].get('rhash') or ''
        peers[rid]['has_rhash'] = _('是') if len(rhash_value) > 1 else _('否')
        _normalize_device_item(peers[rid])

    return [v for k, v in peers.items()]


def get_all_info():
    devices = RustDesDevice.objects.all()
    peers = RustDeskPeer.objects.all()
    devices = {x.rid: model_to_dict2(x) for x in devices}
    now = datetime.datetime.now()
    for peer in peers:
        user = UserProfile.objects.filter(Q(id=peer.uid)).first()
        device = devices.get(peer.rid, None)
        if device and user:
            devices[peer.rid]['rust_user'] = user.username
            devices[peer.rid]['alias'] = peer.alias

    for rid in devices.keys():
        if not devices[rid].get('rust_user', ''):
            devices[rid]['rust_user'] = _('未登录')
        if 'alias' not in devices[rid]:
            devices[rid]['alias'] = ''
        _normalize_device_item(devices[rid])
    for k, v in devices.items():
        try:
            last_update = datetime.datetime.strptime(v['update_time'], '%Y-%m-%d %H:%M')
            devices[k]['status'] = _('在线') if (now - last_update).seconds <= 120 else _('离线')
        except Exception:  # noqa
            devices[k]['status'] = _('未知')
    return [v for k, v in devices.items()]


def _get_current_user(request):
    user = getattr(request, 'user', None)
    if not user or not getattr(user, 'is_authenticated', False):
        return None
    return user


@login_required(login_url='/api/user_action?action=login')
def work(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect('/api/user_action?action=login')
    try:
        _log_event(request, 'front_work_view', username=u.username, show_type=request.GET.get('show_type', ''))
        show_type = request.GET.get('show_type', '')
        show_all = True if show_type == 'admin' and u.is_admin else False
        paginator = Paginator(get_all_info(), 15) if show_type == 'admin' and u.is_admin else Paginator(get_single_info(u.id), 15)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)
        nav_active = 'work_admin' if show_all else 'work'
        return render(
            request,
            'show_work.html',
            {'u': u, 'show_all': show_all, 'page_obj': page_obj, 'nav_active': nav_active},
        )
    except Exception:  # noqa
        logger.exception('work view failed')
        return render(
            request,
            'msg.html',
            {
                'title': _('系统错误'),
                'msg': _('工作台加载失败，请检查数据库迁移与日志输出。'),
                'u': u,
                'nav_active': 'work',
            },
        )


def _summarize_devices(items):
    total = len(items)
    online = 0
    offline = 0
    unknown = 0
    for item in items:
        status = item.get('status', '')
        if status == _('在线'):
            online += 1
        elif status == _('离线'):
            offline += 1
        else:
            unknown += 1
    return {
        'total': total,
        'online': online,
        'offline': offline,
        'unknown': unknown,
    }


def _is_personal_guid(guid):
    return str(guid).startswith("personal-")


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


def _get_profile_access_web(user, guid):
    if guid == _personal_guid(user):
        profile = _ensure_personal_profile(user)
        return profile, user, 3
    profile = AddressBookProfile.objects.filter(Q(guid=guid)).select_related('owner').first()
    if not profile:
        return None, None, 0
    if user.is_admin or str(profile.owner_id) == str(user.id):
        return profile, profile.owner, 3
    rule = _get_rule_access(profile, user)
    if not rule:
        return profile, None, 0
    return profile, profile.owner, rule


def _can_write_rule(rule):
    return rule in (2, 3)


def _ab_accessible_profiles(user, filter_q=None):
    profiles_qs = AddressBookProfile.objects.select_related('owner')
    if not user.is_admin:
        shared_guids = set(AddressBookShare.objects.filter(Q(user=user)).values_list('profile__guid', flat=True))
        rule_qs = AddressBookRule.objects.filter(Q(is_everyone=True) | Q(user=user))
        if user.groups.exists():
            rule_qs = rule_qs | AddressBookRule.objects.filter(Q(group__in=user.groups.all()))
        rule_guids = set(rule_qs.values_list('profile__guid', flat=True))
        accessible_guids = shared_guids | rule_guids
        profiles_qs = profiles_qs.filter(Q(owner=user) | Q(guid__in=accessible_guids))
    if filter_q:
        profiles_qs = profiles_qs.filter(
            Q(name__icontains=filter_q)
            | Q(guid__icontains=filter_q)
            | Q(owner__username__icontains=filter_q)
        )
    return profiles_qs


def _parse_rule(value):
    try:
        rule = int(value)
    except Exception:
        return 1
    return rule if rule in (1, 2, 3) else 1


def _rule_label(rule):
    mapping = {
        1: _('只读'),
        2: _('读写'),
        3: _('完全控制'),
    }
    return mapping.get(rule, str(rule))


def _normalize_tags(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        items = value
    else:
        items = str(value).split(',')
    cleaned = []
    for item in items:
        tag = str(item).strip()
        if tag and tag not in cleaned:
            cleaned.append(tag)
    return cleaned


def _rule_target_info(rule_obj):
    if rule_obj.is_everyone:
        return 'everyone', 'Everyone'
    if rule_obj.group_id:
        return 'group', rule_obj.group.name if rule_obj.group else ''
    if rule_obj.user_id:
        return 'user', rule_obj.user.username if rule_obj.user else ''
    return 'user', ''


def _rule_target_label(target_type):
    mapping = {
        'user': _('用户'),
        'group': _('用户组'),
        'everyone': _('所有人'),
    }
    return mapping.get(target_type, target_type)


def _audit_share(profile, actor, action, share, details=None):
    target_name = share.user.username if share.user else ''
    payload = {'guid': share.guid}
    if details:
        payload.update(details)
    _audit_ab_rule(profile, actor, action, 'user', target_name, share.rule, payload)


def _audit_rule(profile, actor, action, rule_obj, details=None):
    target_type, target_name = _rule_target_info(rule_obj)
    payload = {'guid': rule_obj.guid}
    if details:
        payload.update(details)
    _audit_ab_rule(profile, actor, action, target_type, target_name, rule_obj.rule, payload)


def _apply_rule_change(request, user, action, rule_guid, rule_value=None, details=None):
    share = AddressBookShare.objects.filter(Q(guid=rule_guid)).select_related('profile', 'user').first()
    if share:
        profile = share.profile
        if not profile:
            return False, _('规则不存在。')
        if not user.is_admin and str(profile.owner_id) != str(user.id):
            return False, _('无权限操作该地址簿。')
        if action == 'delete_rule':
            _audit_share(profile, user, 'share_delete', share, details)
            _log_event(request, 'front_ab_share_delete', username=user.username, guid=profile.guid, target=share.user.username if share.user else '')
            share.delete()
            return True, _('用户共享已删除。')
        old_rule = share.rule
        share.rule = rule_value
        share.save()
        _audit_share(profile, user, 'share_update', share, {'before': old_rule, **(details or {})})
        _log_event(request, 'front_ab_share_update', username=user.username, guid=profile.guid, target=share.user.username if share.user else '')
        return True, _('用户共享已更新。')

    rule_obj = AddressBookRule.objects.filter(Q(guid=rule_guid)).select_related('profile', 'user', 'group').first()
    if not rule_obj:
        return False, _('规则不存在。')
    profile = rule_obj.profile
    if not profile:
        return False, _('规则不存在。')
    if not user.is_admin and str(profile.owner_id) != str(user.id):
        return False, _('无权限操作该地址簿。')
    if action == 'delete_rule':
        _audit_rule(profile, user, 'rule_delete', rule_obj, details)
        _log_event(request, 'front_ab_rule_delete', username=user.username, guid=profile.guid)
        rule_obj.delete()
        return True, _('规则已删除。')
    old_rule = rule_obj.rule
    rule_obj.rule = rule_value
    rule_obj.save()
    _audit_rule(profile, user, 'rule_update', rule_obj, {'before': old_rule, **(details or {})})
    _log_event(request, 'front_ab_rule_update', username=user.username, guid=profile.guid)
    return True, _('规则已更新。')


def _collect_global_rules(filter_q=None, allowed_guids=None):
    rules = []
    shares = AddressBookShare.objects.select_related('profile', 'user', 'profile__owner').exclude(profile__guid__startswith='personal-')
    for share in shares:
        profile = share.profile
        if not profile:
            continue
        if allowed_guids is not None and profile.guid not in allowed_guids:
            continue
        rules.append({
            'guid': share.guid,
            'source': 'share',
            'profile_name': profile.name,
            'profile_guid': profile.guid,
            'owner': profile.owner.username if profile.owner else '-',
            'target_type_key': 'user',
            'target_type': _rule_target_label('user'),
            'target_name': share.user.username if share.user else '-',
            'rule': share.rule,
            'rule_label': _rule_label(share.rule),
        })
    rule_rows = AddressBookRule.objects.select_related('profile', 'user', 'group', 'profile__owner').exclude(profile__guid__startswith='personal-')
    for rule in rule_rows:
        profile = rule.profile
        if not profile:
            continue
        if allowed_guids is not None and profile.guid not in allowed_guids:
            continue
        target_type, target_name = _rule_target_info(rule)
        rules.append({
            'guid': rule.guid,
            'source': 'rule',
            'profile_name': profile.name,
            'profile_guid': profile.guid,
            'owner': profile.owner.username if profile.owner else '-',
            'target_type_key': target_type,
            'target_type': _rule_target_label(target_type),
            'target_name': target_name if target_name else '-',
            'rule': rule.rule,
            'rule_label': _rule_label(rule.rule),
        })
    if filter_q:
        q_lower = filter_q.lower()
        rules = [
            r for r in rules
            if q_lower in str(r.get('profile_name', '')).lower()
            or q_lower in str(r.get('profile_guid', '')).lower()
            or q_lower in str(r.get('owner', '')).lower()
            or q_lower in str(r.get('target_name', '')).lower()
        ]
    rules.sort(key=lambda x: (x.get('profile_name', ''), x.get('target_type', ''), x.get('target_name', '')))
    return rules


def _summarize_rules(rules):
    summary = {
        'total': len(rules),
        'user': 0,
        'group': 0,
        'everyone': 0,
        'read': 0,
        'write': 0,
        'full': 0,
    }
    for rule in rules:
        target_type = rule.get('target_type_key')
        if target_type in summary:
            summary[target_type] += 1
        rule_value = rule.get('rule', 0)
        if rule_value == 1:
            summary['read'] += 1
        elif rule_value == 2:
            summary['write'] += 1
        elif rule_value == 3:
            summary['full'] += 1
    return summary

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


@login_required(login_url='/api/user_action?action=login')
def home(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect('/api/user_action?action=login')
    try:
        items = get_all_info() if u.is_admin else get_single_info(u.id)
        summary = _summarize_devices(items)
        recent = sorted(items, key=lambda x: x.get('update_time', ''), reverse=True)[:6]
        _log_event(request, 'front_home_view', username=u.username, total=summary['total'])
        return render(
            request,
            'home.html',
            {
                'u': u,
                'summary': summary,
                'recent': recent,
                'nav_active': 'home',
            },
        )
    except Exception:  # noqa
        logger.exception('home view failed')
        return render(
            request,
            'msg.html',
            {
                'title': _('系统错误'),
                'msg': _('首页加载失败，请检查数据库迁移与日志输出。'),
                'u': u,
                'nav_active': 'home',
            },
        )


@login_required(login_url='/api/user_action?action=login')
def down_peers(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect('/api/user_action?action=login')

    if not u.is_admin:
        logger.debug('down_peers denied, is_admin=%s', u.is_admin)
        _log_event(request, 'front_export_denied', level="warning", username=u.username)
        return HttpResponseRedirect('/api/work')

    _log_event(request, 'front_export_xlsx', username=u.username)
    all_info = get_all_info()
    f = xlwt.Workbook(encoding='utf-8')
    sheet1 = f.add_sheet(_(u'设备信息表'), cell_overwrite_ok=True)
    all_fields = [x.name for x in RustDesDevice._meta.get_fields()]
    all_fields.append('rust_user')
    for i, one in enumerate(all_info):
        for j, name in enumerate(all_fields):
            if i == 0:
                # 写入列名
                sheet1.write(i, j, name)
            sheet1.write(i + 1, j, one.get(name, '-'))

    sio = BytesIO()
    f.save(sio)
    sio.seek(0)
    response = HttpResponse(sio.getvalue(), content_type='application/vnd.ms-excel')
    response['Content-Disposition'] = 'attachment; filename=DeviceInfo.xls'
    response.write(sio.getvalue())
    return response


def check_sharelink_expired(sharelink):
    now = datetime.datetime.now()
    if sharelink.create_time > now:
        return False
    if (now - sharelink.create_time).seconds < 15 * 60:
        return False
    else:
        sharelink.is_expired = True
        sharelink.save()
        return True


@login_required(login_url='/api/user_action?action=login')
def share(request):
    is_admin = getattr(request.user, 'is_admin', False)
    if is_admin:
        peers_qs = RustDeskPeer.objects.all()
        sharelinks_qs = ShareLink.objects.filter(Q(is_used=False) & Q(is_expired=False))
    else:
        peers_qs = RustDeskPeer.objects.filter(Q(uid=request.user.id))
        sharelinks_qs = ShareLink.objects.filter(Q(uid=request.user.id) & Q(is_used=False) & Q(is_expired=False))

    # 省资源：处理已过期请求，不主动定时任务轮询请求，在任意地方请求时，检查是否过期，过期则保存。
    # now = datetime.datetime.now()
    for sl in sharelinks_qs:
        check_sharelink_expired(sl)
    if is_admin:
        sharelinks_qs = ShareLink.objects.filter(Q(is_used=False) & Q(is_expired=False))
    else:
        sharelinks_qs = ShareLink.objects.filter(Q(uid=request.user.id) & Q(is_used=False) & Q(is_expired=False))

    user_map = {}
    if is_admin:
        user_ids = {str(p.uid) for p in peers_qs}
        user_ids.update({str(s.uid) for s in sharelinks_qs})
        if user_ids:
            for user in UserProfile.objects.filter(Q(id__in=user_ids)):
                user_map[str(user.id)] = user.username

    peers = []
    for ix, p in enumerate(peers_qs):
        owner = user_map.get(str(p.uid), p.uid) if is_admin else None
        if is_admin:
            peers.append({'id': ix + 1, 'name': f'{p.rid}|{p.alias}|{owner}'})
        else:
            peers.append({'id': ix + 1, 'name': f'{p.rid}|{p.alias}'})

    sharelinks = []
    for s in sharelinks_qs:
        owner = user_map.get(str(s.uid), s.uid) if is_admin else None
        row = {
            'shash': s.shash,
            'is_used': s.is_used,
            'is_expired': s.is_expired,
            'create_time': s.create_time,
            'peers': s.peers,
        }
        if is_admin:
            row['owner'] = owner
        sharelinks.append(row)

    if request.method == 'GET':
        url = request.build_absolute_uri()
        if url.endswith('share'):
            _log_event(request, 'front_share_view', username=request.user.username)
            return render(
                request,
                'share.html',
                {'peers': peers, 'sharelinks': sharelinks, 'u': request.user, 'nav_active': 'share', 'is_admin': is_admin},
            )
        else:
            shash = url.split('/')[-1]
            sharelink = ShareLink.objects.filter(Q(shash=shash))
            msg = ''
            title = '成功'
            if not sharelink:
                title = '错误'
                msg = f'链接{url}:<br>分享链接不存在或已失效。'
            else:
                sharelink = sharelink[0]
                if str(request.user.id) == str(sharelink.uid):
                    title = '错误'
                    msg = f'链接{url}:<br><br>咱就说，你不能把链接分享给自己吧？！'
                else:
                    sharelink.is_used = True
                    sharelink.save()
                    peers = sharelink.peers
                    peers = peers.split(',')
                    # 自己的peers若重叠，需要跳过
                    peers_self_ids = [x.rid for x in RustDeskPeer.objects.filter(Q(uid=request.user.id))]
                    peers_share = RustDeskPeer.objects.filter(Q(rid__in=peers) & Q(uid=sharelink.uid))
                    # peers_share_ids = [x.rid for x in peers_share]

                    for peer in peers_share:
                        if peer.rid in peers_self_ids:
                            continue
                        # peer = RustDeskPeer.objects.get(rid=peer.rid)
                        peer_f = RustDeskPeer.objects.filter(Q(rid=peer.rid) & Q(uid=sharelink.uid))
                        if not peer_f:
                            msg += f"{peer.rid}已存在,"
                            continue

                        if len(peer_f) > 1:
                            msg += f'{peer.rid}存在多个,已经跳过。 '
                            continue
                        peer = peer_f[0]
                        peer.id = None
                        peer.uid = request.user.id
                        peer.save()
                        msg += f"{peer.rid},"

                    msg += '已被成功获取。'

            title = _(title)
            msg = _(msg)
            _log_event(request, 'front_share_accept', username=request.user.username, shash=shash, status=title)
            return render(
                request,
                'msg.html',
                {'title': title, 'msg': msg, 'u': request.user, 'nav_active': 'share'},
            )
    else:
        data = request.POST.get('data', '[]')
        try:
            data = json.loads(data)
        except Exception:
            _log_event(request, 'front_share_create_failed', level="warning", username=request.user.username, reason='invalid_json')
            return JsonResponse({'code': 0, 'msg': _('数据解析失败。')})
        if not data:
            _log_event(request, 'front_share_create_failed', level="warning", username=request.user.username, reason='empty_data')
            return JsonResponse({'code': 0, 'msg': _('数据为空。')})
        rustdesk_ids = [x['title'].split('|')[0] for x in data]
        rustdesk_ids = [rid for rid in rustdesk_ids if rid]
        if not rustdesk_ids:
            _log_event(request, 'front_share_create_failed', level="warning", username=request.user.username, reason='empty_ids')
            return JsonResponse({'code': 0, 'msg': _('数据为空。')})

        share_uid = request.user.id
        if is_admin:
            owner_ids = list(
                RustDeskPeer.objects.filter(Q(rid__in=rustdesk_ids))
                .values_list('uid', flat=True)
                .distinct()
            )
            if not owner_ids:
                _log_event(request, 'front_share_create_failed', level="warning", username=request.user.username, reason='owner_missing')
                return JsonResponse({'code': 0, 'msg': _('未找到所选设备的归属用户。')})
            if len(owner_ids) > 1:
                _log_event(request, 'front_share_create_failed', level="warning", username=request.user.username, reason='mixed_owner')
                return JsonResponse({'code': 0, 'msg': _('请选择同一用户的设备进行分享。')})
            share_uid = owner_ids[0]
        else:
            own_count = RustDeskPeer.objects.filter(Q(rid__in=rustdesk_ids) & Q(uid=request.user.id)).count()
            if own_count != len(set(rustdesk_ids)):
                _log_event(request, 'front_share_create_failed', level="warning", username=request.user.username, reason='invalid_owner')
                return JsonResponse({'code': 0, 'msg': _('仅支持分享自己名下的设备。')})

        rustdesk_ids = ','.join(rustdesk_ids)
        sharelink = ShareLink(
            uid=share_uid,
            shash=getStrMd5(str(time.time()) + salt),
            peers=rustdesk_ids,
        )
        sharelink.save()
        _log_event(request, 'front_share_create', username=request.user.username, count=len(rustdesk_ids.split(',')))

        return JsonResponse({'code': 1, 'shash': sharelink.shash})


@login_required(login_url='/api/user_action?action=login')
def ab_manage(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect('/api/user_action?action=login')

    filter_q = str(request.GET.get('q', '')).strip()

    if request.method == 'POST':
        filter_q = str(request.POST.get('q', filter_q)).strip()
        action = request.POST.get('action', '')
        if action in ('update_rule', 'delete_rule'):
            rule_value = _parse_rule(request.POST.get('rule', 1))
            rule_guid = request.POST.get('rule_guid', '')
            if not rule_guid:
                messages.error(request, _('规则不存在。'))
                return HttpResponseRedirect('/api/ab_manage')
            ok, msg = _apply_rule_change(request, u, action, rule_guid, rule_value)
            if ok:
                messages.success(request, msg)
            else:
                messages.error(request, msg)
            return HttpResponseRedirect('/api/ab_manage')

        profile_guid = request.POST.get('profile_guid', '')
        rule_value = _parse_rule(request.POST.get('rule', 1))
        profile = AddressBookProfile.objects.filter(Q(guid=profile_guid)).select_related('owner').first()

        if not profile or _is_personal_guid(profile.guid):
            messages.error(request, _('地址簿不存在或不可配置。'))
            return HttpResponseRedirect('/api/ab_manage')

        if not u.is_admin and str(profile.owner_id) != str(u.id):
            messages.error(request, _('无权限操作该地址簿。'))
            return HttpResponseRedirect('/api/ab_manage')

        if action == 'add_user_share':
            user_key = str(request.POST.get('user', '')).strip()
            if not user_key:
                messages.error(request, _('用户不存在。'))
                return HttpResponseRedirect('/api/ab_manage')
            target = UserProfile.objects.filter(Q(username=user_key) | Q(id=user_key)).first()
            if not target:
                messages.error(request, _('用户不存在。'))
                return HttpResponseRedirect('/api/ab_manage')
            share = AddressBookShare.objects.filter(Q(profile=profile) & Q(user=target)).first()
            created = False
            if not share:
                share = AddressBookShare(profile=profile, user=target, rule=rule_value)
                created = True
            else:
                share.rule = rule_value
            share.save()
            action_name = 'share_add' if created else 'share_update'
            _audit_share(profile, u, action_name, share, {'created': created})
            _log_event(request, 'front_ab_share_add', username=u.username, guid=profile_guid, target=target.username)
            messages.success(request, _('用户共享已更新。'))
            return HttpResponseRedirect('/api/ab_manage')

        if action == 'add_group_rule':
            group_key = str(request.POST.get('group', '')).strip()
            if not group_key:
                messages.error(request, _('用户组不存在。'))
                return HttpResponseRedirect('/api/ab_manage')
            group = Group.objects.filter(Q(name=group_key) | Q(id=group_key)).first()
            if not group:
                messages.error(request, _('用户组不存在。'))
                return HttpResponseRedirect('/api/ab_manage')
            rule_obj = AddressBookRule.objects.filter(Q(profile=profile) & Q(group=group)).first()
            created = False
            if not rule_obj:
                rule_obj = AddressBookRule(profile=profile, group=group, rule=rule_value)
                created = True
            else:
                rule_obj.rule = rule_value
            rule_obj.is_everyone = False
            rule_obj.save()
            action_name = 'rule_add' if created else 'rule_update'
            _audit_rule(profile, u, action_name, rule_obj, {'created': created})
            _log_event(request, 'front_ab_rule_group_add', username=u.username, guid=profile_guid, group=group.name)
            messages.success(request, _('组规则已更新。'))
            return HttpResponseRedirect('/api/ab_manage')

        if action == 'add_everyone_rule':
            rule_obj = AddressBookRule.objects.filter(Q(profile=profile) & Q(is_everyone=True)).first()
            created = False
            if not rule_obj:
                rule_obj = AddressBookRule(profile=profile, rule=rule_value, is_everyone=True)
                created = True
            else:
                rule_obj.rule = rule_value
            rule_obj.save()
            action_name = 'rule_add' if created else 'rule_update'
            _audit_rule(profile, u, action_name, rule_obj, {'created': created})
            _log_event(request, 'front_ab_rule_everyone_add', username=u.username, guid=profile_guid)
            messages.success(request, _('Everyone 规则已更新。'))
            return HttpResponseRedirect('/api/ab_manage')

        messages.error(request, _('操作失败。'))
        return HttpResponseRedirect('/api/ab_manage')

    profiles_qs = AddressBookProfile.objects.exclude(guid__startswith='personal-').select_related('owner')
    if not u.is_admin:
        profiles_qs = profiles_qs.filter(owner=u)
    if filter_q:
        profiles_qs = profiles_qs.filter(
            Q(name__icontains=filter_q)
            | Q(guid__icontains=filter_q)
            | Q(owner__username__icontains=filter_q)
        )

    profiles = []
    for profile in profiles_qs.order_by('name'):
        shares = AddressBookShare.objects.filter(profile=profile).select_related('user')
        user_rules = AddressBookRule.objects.filter(profile=profile, user__isnull=False).select_related('user')
        group_rules = AddressBookRule.objects.filter(profile=profile, group__isnull=False).select_related('group')
        everyone_rule = AddressBookRule.objects.filter(profile=profile, is_everyone=True).first()

        user_entries = [
            {
                'guid': s.guid,
                'name': s.user.username if s.user else '-',
                'rule': s.rule,
                'rule_label': _rule_label(s.rule),
            }
            for s in shares
        ]
        for r in user_rules:
            user_entries.append({
                'guid': r.guid,
                'name': r.user.username if r.user else '-',
                'rule': r.rule,
                'rule_label': _rule_label(r.rule),
            })
        user_entries.sort(key=lambda x: x['name'])

        group_entries = [
            {
                'guid': r.guid,
                'name': r.group.name if r.group else '-',
                'rule': r.rule,
                'rule_label': _rule_label(r.rule),
            }
            for r in group_rules
        ]
        group_entries.sort(key=lambda x: x['name'])

        profiles.append({
            'profile': profile,
            'user_entries': user_entries,
            'group_entries': group_entries,
            'everyone_rule': {
                'guid': everyone_rule.guid,
                'rule': everyone_rule.rule,
                'rule_label': _rule_label(everyone_rule.rule),
            } if everyone_rule else None,
            'can_manage': u.is_admin or str(profile.owner_id) == str(u.id),
        })

    rule_choices = [
        (1, _('只读')),
        (2, _('读写')),
        (3, _('完全控制')),
    ]

    global_rules = []
    rule_stats = None
    if u.is_admin:
        global_rules = _collect_global_rules(filter_q)
        rule_stats = _summarize_rules(global_rules)

    return render(
        request,
        'ab_manage.html',
        {
            'u': u,
            'profiles': profiles,
            'global_rules': global_rules,
            'rule_stats': rule_stats,
            'filter_q': filter_q,
            'groups': Group.objects.all().order_by('name'),
            'rule_choices': rule_choices,
            'nav_active': 'ab_manage',
        },
    )


@login_required(login_url='/api/user_action?action=login')
def ab_books(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect('/api/user_action?action=login')

    filter_q = str(request.GET.get('q', '')).strip()

    if request.method == 'POST':
        action = request.POST.get('action', '')
        if action == 'create_book':
            name = str(request.POST.get('name', '')).strip()
            note = str(request.POST.get('note', '')).strip()
            owner_key = str(request.POST.get('owner', '')).strip()
            if not name:
                messages.error(request, _('地址簿名称不能为空。'))
                return HttpResponseRedirect('/api/ab_books')
            if name in ("My address book", "Legacy address book", "我的地址簿", "旧版地址簿"):
                messages.error(request, _('地址簿名称为保留名称。'))
                return HttpResponseRedirect('/api/ab_books')
            owner = u
            if u.is_admin and owner_key:
                owner = UserProfile.objects.filter(Q(username=owner_key) | Q(id=owner_key)).first()
                if not owner:
                    messages.error(request, _('目标用户不存在。'))
                    return HttpResponseRedirect('/api/ab_books')
            if AddressBookProfile.objects.filter(Q(owner=owner) & Q(name=name)).exists():
                messages.error(request, _('地址簿名称已存在。'))
                return HttpResponseRedirect('/api/ab_books')
            profile = AddressBookProfile(
                guid=uuid.uuid4().hex,
                name=name,
                owner=owner,
                rule=3,
                note=note or '',
            )
            profile.save()
            _log_event(request, 'front_ab_book_create', username=u.username, guid=profile.guid, owner=owner.username)
            messages.success(request, _('地址簿已创建。'))
            return HttpResponseRedirect('/api/ab_books')

        if action == 'update_book':
            guid = request.POST.get('guid', '')
            profile = AddressBookProfile.objects.filter(Q(guid=guid)).select_related('owner').first()
            if not profile:
                messages.error(request, _('地址簿不存在。'))
                return HttpResponseRedirect('/api/ab_books')
            if _is_personal_guid(profile.guid):
                messages.error(request, _('个人地址簿不可修改。'))
                return HttpResponseRedirect('/api/ab_books')
            if not u.is_admin and str(profile.owner_id) != str(u.id):
                messages.error(request, _('无权限操作该地址簿。'))
                return HttpResponseRedirect('/api/ab_books')
            name = str(request.POST.get('name', '')).strip()
            note = str(request.POST.get('note', '')).strip()
            if name and name != profile.name:
                if name in ("My address book", "Legacy address book", "我的地址簿", "旧版地址簿"):
                    messages.error(request, _('地址簿名称为保留名称。'))
                    return HttpResponseRedirect('/api/ab_books')
                if AddressBookProfile.objects.filter(Q(owner=profile.owner) & Q(name=name)).exclude(pk=profile.pk).exists():
                    messages.error(request, _('地址簿名称已存在。'))
                    return HttpResponseRedirect('/api/ab_books')
                profile.name = name
            if note is not None:
                profile.note = note
            profile.save()
            _log_event(request, 'front_ab_book_update', username=u.username, guid=profile.guid)
            messages.success(request, _('地址簿已更新。'))
            return HttpResponseRedirect('/api/ab_books')

        if action == 'delete_book':
            guid = request.POST.get('guid', '')
            profile = AddressBookProfile.objects.filter(Q(guid=guid)).select_related('owner').first()
            if not profile:
                messages.error(request, _('地址簿不存在。'))
                return HttpResponseRedirect('/api/ab_books')
            if _is_personal_guid(profile.guid):
                messages.error(request, _('个人地址簿不可删除。'))
                return HttpResponseRedirect('/api/ab_books')
            if not u.is_admin and str(profile.owner_id) != str(u.id):
                messages.error(request, _('无权限操作该地址簿。'))
                return HttpResponseRedirect('/api/ab_books')
            RustDeskPeer.objects.filter(Q(uid=profile.owner_id) & Q(profile_guid=guid)).delete()
            RustDeskTag.objects.filter(Q(uid=profile.owner_id) & Q(profile_guid=guid)).delete()
            AddressBookRule.objects.filter(Q(profile=profile)).delete()
            AddressBookShare.objects.filter(Q(profile=profile)).delete()
            profile.delete()
            _log_event(request, 'front_ab_book_delete', username=u.username, guid=guid)
            messages.success(request, _('地址簿已删除。'))
            return HttpResponseRedirect('/api/ab_books')

        if action == 'transfer_book':
            if not u.is_admin:
                messages.error(request, _('无权限操作该地址簿。'))
                return HttpResponseRedirect('/api/ab_books')
            guid = request.POST.get('guid', '')
            target_key = str(request.POST.get('owner', '')).strip()
            profile = AddressBookProfile.objects.filter(Q(guid=guid)).select_related('owner').first()
            if not profile:
                messages.error(request, _('地址簿不存在。'))
                return HttpResponseRedirect('/api/ab_books')
            if _is_personal_guid(profile.guid):
                messages.error(request, _('个人地址簿不可修改。'))
                return HttpResponseRedirect('/api/ab_books')
            if not target_key:
                messages.error(request, _('目标用户不存在。'))
                return HttpResponseRedirect('/api/ab_books')
            new_owner = UserProfile.objects.filter(Q(username=target_key) | Q(id=target_key)).first()
            if not new_owner:
                messages.error(request, _('目标用户不存在。'))
                return HttpResponseRedirect('/api/ab_books')
            old_owner_id = profile.owner_id
            if str(old_owner_id) != str(new_owner.id):
                profile.owner = new_owner
                profile.save(update_fields=['owner', 'updated_at'])
                RustDeskPeer.objects.filter(Q(uid=str(old_owner_id)) & Q(profile_guid=profile.guid)).update(uid=str(new_owner.id))
                RustDeskTag.objects.filter(Q(uid=str(old_owner_id)) & Q(profile_guid=profile.guid)).update(uid=str(new_owner.id))
            _log_event(request, 'front_ab_book_transfer', username=u.username, guid=profile.guid, owner=new_owner.username)
            messages.success(request, _('地址簿已更新。'))
            return HttpResponseRedirect('/api/ab_books')

    profiles_qs = _ab_accessible_profiles(u, filter_q)

    profiles = []
    for profile in profiles_qs.order_by('name'):
        is_personal = _is_personal_guid(profile.guid)
        if is_personal:
            RustDeskPeer.objects.filter(Q(uid=profile.owner_id) & Q(profile_guid='')).update(profile_guid=profile.guid)
            RustDeskTag.objects.filter(Q(uid=profile.owner_id) & Q(profile_guid='')).update(profile_guid=profile.guid)
        peers_count = RustDeskPeer.objects.filter(Q(uid=profile.owner_id) & Q(profile_guid=profile.guid)).count()
        tags_count = RustDeskTag.objects.filter(Q(uid=profile.owner_id) & Q(profile_guid=profile.guid)).count()
        access_rule = 3 if (u.is_admin or str(profile.owner_id) == str(u.id)) else _get_rule_access(profile, u)
        can_edit = u.is_admin or str(profile.owner_id) == str(u.id) or _can_write_rule(access_rule)
        profiles.append({
            'profile': profile,
            'is_personal': is_personal,
            'peers_count': peers_count,
            'tags_count': tags_count,
            'access_rule': access_rule,
            'access_label': _rule_label(access_rule) if access_rule else _('无权限'),
            'can_manage': u.is_admin or str(profile.owner_id) == str(u.id),
            'can_edit': can_edit,
        })

    _log_event(request, 'front_ab_books_view', username=u.username, total=len(profiles))
    return render(
        request,
        'ab_books.html',
        {
            'u': u,
            'profiles': profiles,
            'filter_q': filter_q,
            'nav_active': 'ab_books',
        },
    )


@login_required(login_url='/api/user_action?action=login')
def ab_books_export(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect('/api/user_action?action=login')
    export_format = str(request.GET.get('format', 'csv')).lower()
    filter_q = str(request.GET.get('q', '')).strip()
    profiles_qs = _ab_accessible_profiles(u, filter_q).order_by('name')
    profiles = list(profiles_qs)
    filename_stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M')

    headers = [_('地址簿名称'), _('地址簿 GUID'), _('所属用户'), _('备注（可选）'), _('设备'), _('标签')]

    if export_format in ('xls', 'xlsx'):
        workbook = xlwt.Workbook(encoding='utf-8')
        sheet = workbook.add_sheet(_('地址簿列表'), cell_overwrite_ok=True)
        for col, header in enumerate(headers):
            sheet.write(0, col, header)
        for row, profile in enumerate(profiles, start=1):
            peers_count = RustDeskPeer.objects.filter(Q(uid=profile.owner_id) & Q(profile_guid=profile.guid)).count()
            tags_count = RustDeskTag.objects.filter(Q(uid=profile.owner_id) & Q(profile_guid=profile.guid)).count()
            sheet.write(row, 0, profile.name)
            sheet.write(row, 1, profile.guid)
            sheet.write(row, 2, profile.owner.username if profile.owner else '-')
            sheet.write(row, 3, profile.note or '')
            sheet.write(row, 4, peers_count)
            sheet.write(row, 5, tags_count)
        sio = BytesIO()
        workbook.save(sio)
        sio.seek(0)
        response = HttpResponse(sio.getvalue(), content_type='application/vnd.ms-excel')
        response['Content-Disposition'] = f'attachment; filename=ab_books_{filename_stamp}.xls'
        _log_event(request, 'front_ab_books_export', username=u.username, count=len(profiles))
        return response

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    for profile in profiles:
        peers_count = RustDeskPeer.objects.filter(Q(uid=profile.owner_id) & Q(profile_guid=profile.guid)).count()
        tags_count = RustDeskTag.objects.filter(Q(uid=profile.owner_id) & Q(profile_guid=profile.guid)).count()
        writer.writerow([
            profile.name,
            profile.guid,
            profile.owner.username if profile.owner else '-',
            profile.note or '',
            peers_count,
            tags_count,
        ])
    response = HttpResponse(output.getvalue(), content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = f'attachment; filename=ab_books_{filename_stamp}.csv'
    _log_event(request, 'front_ab_books_export', username=u.username, count=len(profiles))
    return response


@login_required(login_url='/api/user_action?action=login')
def ab_book(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect('/api/user_action?action=login')

    guid = request.GET.get('guid', '') or request.POST.get('guid', '')
    if not guid:
        messages.error(request, _('地址簿不存在。'))
        return HttpResponseRedirect('/api/ab_books')

    profile, owner, rule = _get_profile_access_web(u, guid)
    if not profile:
        messages.error(request, _('地址簿不存在。'))
        return HttpResponseRedirect('/api/ab_books')
    if not owner and not u.is_admin:
        messages.error(request, _('无权限操作该地址簿。'))
        return HttpResponseRedirect('/api/ab_books')

    can_edit = u.is_admin or str(profile.owner_id) == str(u.id) or _can_write_rule(rule)
    is_personal = _is_personal_guid(profile.guid)
    if is_personal:
        RustDeskPeer.objects.filter(Q(uid=owner.id) & Q(profile_guid='')).update(profile_guid=profile.guid)
        RustDeskTag.objects.filter(Q(uid=owner.id) & Q(profile_guid='')).update(profile_guid=profile.guid)

    if request.method == 'POST':
        action = request.POST.get('action', '')
        if not can_edit:
            messages.error(request, _('当前权限不足以修改地址簿内容。'))
            return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')

        if action in ('bulk_tag_add', 'bulk_tag_remove', 'bulk_tag_replace', 'bulk_note_update', 'bulk_peer_delete'):
            peer_ids = request.POST.getlist('peer_ids')
            tags_input = request.POST.get('tags', '')
            tags = _normalize_tags(tags_input)
            if not peer_ids:
                messages.error(request, _('请选择至少一台设备。'))
                return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')
            peers_qs = RustDeskPeer.objects.filter(Q(uid=owner.id) & Q(profile_guid=profile.guid) & Q(rid__in=peer_ids))
            updated = 0
            if action in ('bulk_tag_add', 'bulk_tag_remove', 'bulk_tag_replace'):
                for peer in peers_qs:
                    existing = _normalize_tags(peer.tags)
                    if action == 'bulk_tag_add':
                        new_tags = existing[:]
                        for tag in tags:
                            if tag not in new_tags:
                                new_tags.append(tag)
                    elif action == 'bulk_tag_remove':
                        new_tags = [t for t in existing if t not in tags]
                    else:
                        new_tags = tags[:]
                    peer.tags = ','.join(new_tags)
                    peer.save()
                    updated += 1
                    for tag_name in new_tags:
                        if not RustDeskTag.objects.filter(Q(uid=owner.id) & Q(profile_guid=profile.guid) & Q(tag_name=tag_name)).exists():
                            RustDeskTag(uid=owner.id, tag_name=tag_name, tag_color='', profile_guid=profile.guid).save()
                _log_event(request, 'front_ab_bulk_tag', username=u.username, guid=profile.guid, action=action, count=updated)
                messages.success(request, _('已批量更新 %(count)s 台设备标签。') % {'count': updated})
                return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')

            if action == 'bulk_note_update':
                note_value = str(request.POST.get('note', '')).strip()
                for peer in peers_qs:
                    peer.note = note_value
                    peer.save()
                    updated += 1
                _log_event(request, 'front_ab_bulk_note', username=u.username, guid=profile.guid, count=updated)
                messages.success(request, _('已批量更新 %(count)s 台设备备注。') % {'count': updated})
                return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')

            if action == 'bulk_peer_delete':
                deleted = peers_qs.count()
                peers_qs.delete()
                _log_event(request, 'front_ab_bulk_delete', username=u.username, guid=profile.guid, count=deleted)
                messages.success(request, _('已批量删除 %(count)s 台设备。') % {'count': deleted})
                return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')

        if action == 'add_tag':
            name = str(request.POST.get('name', '')).strip()
            color = str(request.POST.get('color', '')).strip()
            if not name:
                messages.error(request, _('标签名称不能为空。'))
                return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')
            if not RustDeskTag.objects.filter(Q(uid=owner.id) & Q(profile_guid=profile.guid) & Q(tag_name=name)).first():
                RustDeskTag(uid=owner.id, tag_name=name, tag_color=color, profile_guid=profile.guid).save()
            else:
                RustDeskTag.objects.filter(Q(uid=owner.id) & Q(profile_guid=profile.guid) & Q(tag_name=name)).update(tag_color=color)
            _log_event(request, 'front_ab_tag_add', username=u.username, guid=profile.guid, tag=name)
            messages.success(request, _('标签已更新。'))
            return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')

        if action == 'rename_tag':
            old = str(request.POST.get('old', '')).strip()
            new = str(request.POST.get('new', '')).strip()
            if not old or not new:
                messages.error(request, _('标签名称不能为空。'))
                return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')
            RustDeskTag.objects.filter(Q(uid=owner.id) & Q(profile_guid=profile.guid) & Q(tag_name=old)).update(tag_name=new)
            peers = RustDeskPeer.objects.filter(Q(uid=owner.id) & Q(profile_guid=profile.guid))
            for peer in peers:
                tags = [x for x in peer.tags.split(',') if x]
                if old in tags:
                    tags = [new if x == old else x for x in tags]
                    peer.tags = ','.join(tags)
                    peer.save()
            _log_event(request, 'front_ab_tag_rename', username=u.username, guid=profile.guid, old=old, new=new)
            messages.success(request, _('标签已重命名。'))
            return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')

        if action == 'update_tag':
            name = str(request.POST.get('name', '')).strip()
            color = str(request.POST.get('color', '')).strip()
            if not name:
                messages.error(request, _('标签名称不能为空。'))
                return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')
            RustDeskTag.objects.filter(Q(uid=owner.id) & Q(profile_guid=profile.guid) & Q(tag_name=name)).update(tag_color=color)
            _log_event(request, 'front_ab_tag_update', username=u.username, guid=profile.guid, tag=name)
            messages.success(request, _('标签颜色已更新。'))
            return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')

        if action == 'delete_tag':
            name = str(request.POST.get('name', '')).strip()
            if not name:
                messages.error(request, _('标签名称不能为空。'))
                return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')
            RustDeskTag.objects.filter(Q(uid=owner.id) & Q(profile_guid=profile.guid) & Q(tag_name=name)).delete()
            peers = RustDeskPeer.objects.filter(Q(uid=owner.id) & Q(profile_guid=profile.guid))
            for peer in peers:
                tags = [x for x in peer.tags.split(',') if x and x != name]
                peer.tags = ','.join(tags)
                peer.save()
            _log_event(request, 'front_ab_tag_delete', username=u.username, guid=profile.guid, tag=name)
            messages.success(request, _('标签已删除。'))
            return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')

        if action == 'add_peer':
            rid = str(request.POST.get('rid', '')).strip()
            alias = str(request.POST.get('alias', '')).strip()
            note = str(request.POST.get('note', '')).strip()
            tags = _normalize_tags(request.POST.get('tags', ''))
            password = str(request.POST.get('password', '')).strip()
            if not rid:
                messages.error(request, _('设备ID不能为空。'))
                return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')
            peer = RustDeskPeer.objects.filter(Q(uid=owner.id) & Q(rid=rid) & Q(profile_guid=profile.guid)).first()
            tags_str = ','.join(tags)
            if peer:
                peer.alias = alias or peer.alias
                peer.note = note
                peer.tags = tags_str
                if not is_personal and password:
                    peer.password = password
                peer.save()
                _log_event(request, 'front_ab_peer_update', username=u.username, guid=profile.guid, rid=rid)
                messages.success(request, _('设备已更新。'))
            else:
                peer = RustDeskPeer(
                    uid=str(owner.id),
                    rid=rid,
                    username='',
                    hostname='',
                    alias=alias or rid,
                    platform='',
                    tags=tags_str,
                    rhash='',
                    note=note or '',
                    password='' if is_personal else password,
                    device_group_name='',
                    login_name='',
                    same_server=False,
                    profile_guid=profile.guid,
                )
                peer.save()
                _log_event(request, 'front_ab_peer_add', username=u.username, guid=profile.guid, rid=rid)
                messages.success(request, _('设备已新增。'))
            for tag_name in tags:
                if not RustDeskTag.objects.filter(Q(uid=owner.id) & Q(profile_guid=profile.guid) & Q(tag_name=tag_name)).exists():
                    RustDeskTag(uid=owner.id, tag_name=tag_name, tag_color='', profile_guid=profile.guid).save()
            return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')

        if action == 'update_peer':
            rid = str(request.POST.get('rid', '')).strip()
            alias = str(request.POST.get('alias', '')).strip()
            note = str(request.POST.get('note', '')).strip()
            tags = _normalize_tags(request.POST.get('tags', ''))
            password = str(request.POST.get('password', '')).strip()
            if not rid:
                messages.error(request, _('设备ID不能为空。'))
                return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')
            peer = RustDeskPeer.objects.filter(Q(uid=owner.id) & Q(rid=rid) & Q(profile_guid=profile.guid)).first()
            if not peer:
                messages.error(request, _('设备不存在。'))
                return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')
            peer.alias = alias or peer.alias
            peer.note = note
            peer.tags = ','.join(tags)
            if not is_personal and password:
                peer.password = password
            peer.save()
            for tag_name in tags:
                if not RustDeskTag.objects.filter(Q(uid=owner.id) & Q(profile_guid=profile.guid) & Q(tag_name=tag_name)).exists():
                    RustDeskTag(uid=owner.id, tag_name=tag_name, tag_color='', profile_guid=profile.guid).save()
            _log_event(request, 'front_ab_peer_update', username=u.username, guid=profile.guid, rid=rid)
            messages.success(request, _('设备已更新。'))
            return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')

        if action == 'delete_peer':
            rid = str(request.POST.get('rid', '')).strip()
            if not rid:
                messages.error(request, _('设备ID不能为空。'))
                return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')
            RustDeskPeer.objects.filter(Q(uid=owner.id) & Q(profile_guid=profile.guid) & Q(rid=rid)).delete()
            _log_event(request, 'front_ab_peer_delete', username=u.username, guid=profile.guid, rid=rid)
            messages.success(request, _('设备已删除。'))
            return HttpResponseRedirect(f'/api/ab_book?guid={profile.guid}')

    peers = list(RustDeskPeer.objects.filter(Q(uid=owner.id) & Q(profile_guid=profile.guid)))
    peers.sort(key=lambda x: x.rid)

    return render(
        request,
        'ab_book.html',
        {
            'u': u,
            'profile': profile,
            'owner': owner,
            'peers': peers,
            'can_edit': can_edit,
            'is_personal': is_personal,
            'rule_label': _rule_label(rule) if rule else _('无权限'),
            'nav_active': 'ab_books',
        },
    )


@login_required(login_url='/api/user_action?action=login')
def ab_book_export(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect('/api/user_action?action=login')
    guid = request.GET.get('guid', '')
    kind = str(request.GET.get('kind', 'peers')).lower()
    export_format = str(request.GET.get('format', 'csv')).lower()
    profile, owner, rule = _get_profile_access_web(u, guid)
    if not profile:
        return HttpResponseRedirect('/api/ab_books')
    if not owner and not u.is_admin:
        return HttpResponseRedirect('/api/ab_books')

    filename_stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M')
    if kind == 'tags':
        rows = list(RustDeskTag.objects.filter(Q(uid=owner.id) & Q(profile_guid=profile.guid)))
        headers = [_('标签名称'), _('颜色')]
        if export_format in ('xls', 'xlsx'):
            workbook = xlwt.Workbook(encoding='utf-8')
            sheet = workbook.add_sheet(_('标签列表'), cell_overwrite_ok=True)
            for col, header in enumerate(headers):
                sheet.write(0, col, header)
            for row, tag in enumerate(rows, start=1):
                sheet.write(row, 0, tag.tag_name)
                sheet.write(row, 1, tag.tag_color)
            sio = BytesIO()
            workbook.save(sio)
            sio.seek(0)
            response = HttpResponse(sio.getvalue(), content_type='application/vnd.ms-excel')
            response['Content-Disposition'] = f'attachment; filename=ab_tags_{filename_stamp}.xls'
            _log_event(request, 'front_ab_book_export', username=u.username, guid=profile.guid, kind='tags')
            return response
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        for tag in rows:
            writer.writerow([tag.tag_name, tag.tag_color])
        response = HttpResponse(output.getvalue(), content_type='text/csv; charset=utf-8')
        response['Content-Disposition'] = f'attachment; filename=ab_tags_{filename_stamp}.csv'
        _log_event(request, 'front_ab_book_export', username=u.username, guid=profile.guid, kind='tags')
        return response

    rows = list(RustDeskPeer.objects.filter(Q(uid=owner.id) & Q(profile_guid=profile.guid)))
    headers = [_('设备ID'), _('别名'), _('备注'), _('标签'), _('共享密码（可选）')]
    if export_format in ('xls', 'xlsx'):
        workbook = xlwt.Workbook(encoding='utf-8')
        sheet = workbook.add_sheet(_('设备列表'), cell_overwrite_ok=True)
        for col, header in enumerate(headers):
            sheet.write(0, col, header)
        for row, peer in enumerate(rows, start=1):
            sheet.write(row, 0, peer.rid)
            sheet.write(row, 1, peer.alias)
            sheet.write(row, 2, peer.note or '')
            sheet.write(row, 3, peer.tags)
            sheet.write(row, 4, peer.password if not _is_personal_guid(profile.guid) else '')
        sio = BytesIO()
        workbook.save(sio)
        sio.seek(0)
        response = HttpResponse(sio.getvalue(), content_type='application/vnd.ms-excel')
        response['Content-Disposition'] = f'attachment; filename=ab_peers_{filename_stamp}.xls'
        _log_event(request, 'front_ab_book_export', username=u.username, guid=profile.guid, kind='peers')
        return response

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    for peer in rows:
        writer.writerow([
            peer.rid,
            peer.alias,
            peer.note or '',
            peer.tags,
            peer.password if not _is_personal_guid(profile.guid) else '',
        ])
    response = HttpResponse(output.getvalue(), content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = f'attachment; filename=ab_peers_{filename_stamp}.csv'
    _log_event(request, 'front_ab_book_export', username=u.username, guid=profile.guid, kind='peers')
    return response


@login_required(login_url='/api/user_action?action=login')
def tag_manage(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect('/api/user_action?action=login')

    filter_q = str(request.GET.get('q', '')).strip()
    profiles_qs = _ab_accessible_profiles(u, None).select_related('owner')
    profiles = list(profiles_qs)
    profile_map = {p.guid: p for p in profiles}
    create_profiles = []
    for profile in profiles:
        access_rule = 3 if (u.is_admin or str(profile.owner_id) == str(u.id)) else _get_rule_access(profile, u)
        if _can_write_rule(access_rule):
            create_profiles.append(profile)

    if request.method == 'POST':
        action = request.POST.get('action', '')
        profile_guid = str(request.POST.get('profile_guid', '')).strip()
        target_profile = profile_map.get(profile_guid)
        if not target_profile:
            messages.error(request, _('地址簿不存在。'))
            return HttpResponseRedirect('/api/tag_manage')
        access_rule = 3 if (u.is_admin or str(target_profile.owner_id) == str(u.id)) else _get_rule_access(target_profile, u)
        if not _can_write_rule(access_rule):
            messages.error(request, _('无权限操作该地址簿。'))
            return HttpResponseRedirect('/api/tag_manage')

        if action == 'add_tag':
            name = str(request.POST.get('name', '')).strip()
            color = str(request.POST.get('color', '')).strip()
            if not name:
                messages.error(request, _('标签名称不能为空。'))
                return HttpResponseRedirect('/api/tag_manage')
            tag = RustDeskTag.objects.filter(Q(uid=target_profile.owner_id) & Q(profile_guid=profile_guid) & Q(tag_name=name)).first()
            if tag:
                tag.tag_color = color
                tag.save()
            else:
                RustDeskTag(uid=target_profile.owner_id, tag_name=name, tag_color=color, profile_guid=profile_guid).save()
            _log_event(request, 'front_tag_add', username=u.username, guid=profile_guid, tag=name)
            messages.success(request, _('标签已更新。'))
            return HttpResponseRedirect('/api/tag_manage')

        if action == 'update_tag':
            name = str(request.POST.get('name', '')).strip()
            color = str(request.POST.get('color', '')).strip()
            if not name:
                messages.error(request, _('标签名称不能为空。'))
                return HttpResponseRedirect('/api/tag_manage')
            RustDeskTag.objects.filter(Q(uid=target_profile.owner_id) & Q(profile_guid=profile_guid) & Q(tag_name=name)).update(tag_color=color)
            _log_event(request, 'front_tag_update', username=u.username, guid=profile_guid, tag=name)
            messages.success(request, _('标签颜色已更新。'))
            return HttpResponseRedirect('/api/tag_manage')

        if action == 'rename_tag':
            old = str(request.POST.get('old', '')).strip()
            new = str(request.POST.get('new', '')).strip()
            if not old or not new:
                messages.error(request, _('标签名称不能为空。'))
                return HttpResponseRedirect('/api/tag_manage')
            if old == new:
                messages.success(request, _('标签已重命名。'))
                return HttpResponseRedirect('/api/tag_manage')
            existing = RustDeskTag.objects.filter(Q(uid=target_profile.owner_id) & Q(profile_guid=profile_guid) & Q(tag_name=new)).first()
            if not existing:
                RustDeskTag.objects.filter(Q(uid=target_profile.owner_id) & Q(profile_guid=profile_guid) & Q(tag_name=old)).update(tag_name=new)
            peers = RustDeskPeer.objects.filter(Q(uid=target_profile.owner_id) & Q(profile_guid=profile_guid))
            for p in peers:
                tags = [x for x in p.tags.split(',') if x]
                if old in tags:
                    tags = [new if x == old else x for x in tags]
                    p.tags = ','.join(tags)
                    p.save()
            if existing:
                RustDeskTag.objects.filter(Q(uid=target_profile.owner_id) & Q(profile_guid=profile_guid) & Q(tag_name=old)).delete()
            _log_event(request, 'front_tag_rename', username=u.username, guid=profile_guid, old=old, new=new)
            messages.success(request, _('标签已重命名。'))
            return HttpResponseRedirect('/api/tag_manage')

        if action == 'delete_tag':
            name = str(request.POST.get('name', '')).strip()
            if not name:
                messages.error(request, _('标签名称不能为空。'))
                return HttpResponseRedirect('/api/tag_manage')
            RustDeskTag.objects.filter(Q(uid=target_profile.owner_id) & Q(profile_guid=profile_guid) & Q(tag_name=name)).delete()
            peers = RustDeskPeer.objects.filter(Q(uid=target_profile.owner_id) & Q(profile_guid=profile_guid))
            for p in peers:
                tags = [x for x in p.tags.split(',') if x and x != name]
                p.tags = ','.join(tags)
                p.save()
            _log_event(request, 'front_tag_delete', username=u.username, guid=profile_guid, tag=name)
            messages.success(request, _('标签已删除。'))
            return HttpResponseRedirect('/api/tag_manage')

    tag_rows = RustDeskTag.objects.filter(profile_guid__in=list(profile_map.keys()))
    if filter_q:
        tag_rows = tag_rows.filter(
            Q(tag_name__icontains=filter_q)
            | Q(profile_guid__icontains=filter_q)
        )
    tags = []
    for tag in tag_rows.order_by('tag_name'):
        profile = profile_map.get(tag.profile_guid)
        if not profile:
            continue
        access_rule = 3 if (u.is_admin or str(profile.owner_id) == str(u.id)) else _get_rule_access(profile, u)
        tags.append({
            'name': tag.tag_name,
            'color': tag.tag_color,
            'profile_guid': tag.profile_guid,
            'profile_name': profile.name,
            'owner': profile.owner.username if profile.owner else '-',
            'can_edit': _can_write_rule(access_rule),
        })

    _log_event(request, 'front_tag_manage_view', username=u.username, total=len(tags))
    return render(
        request,
        'tag_manage.html',
        {
            'u': u,
            'profiles': create_profiles,
            'tags': tags,
            'filter_q': filter_q,
            'nav_active': 'tag_manage',
        },
    )


@login_required(login_url='/api/user_action?action=login')
def tag_export(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect('/api/user_action?action=login')
    export_format = str(request.GET.get('format', 'csv')).lower()
    filter_q = str(request.GET.get('q', '')).strip()
    profiles = list(_ab_accessible_profiles(u, None).select_related('owner'))
    profile_map = {p.guid: p for p in profiles}
    tags_qs = RustDeskTag.objects.filter(profile_guid__in=list(profile_map.keys()))
    if filter_q:
        tags_qs = tags_qs.filter(
            Q(tag_name__icontains=filter_q)
            | Q(profile_guid__icontains=filter_q)
        )
    rows = list(tags_qs.order_by('tag_name'))
    filename_stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M')
    headers = [_('标签名称'), _('颜色'), _('地址簿'), _('地址簿 GUID'), _('所属用户')]

    if export_format in ('xls', 'xlsx'):
        workbook = xlwt.Workbook(encoding='utf-8')
        sheet = workbook.add_sheet(_('标签列表'), cell_overwrite_ok=True)
        for col, header in enumerate(headers):
            sheet.write(0, col, header)
        for row, tag in enumerate(rows, start=1):
            profile = profile_map.get(tag.profile_guid)
            sheet.write(row, 0, tag.tag_name)
            sheet.write(row, 1, tag.tag_color)
            sheet.write(row, 2, profile.name if profile else '')
            sheet.write(row, 3, tag.profile_guid)
            sheet.write(row, 4, profile.owner.username if profile and profile.owner else '-')
        sio = BytesIO()
        workbook.save(sio)
        sio.seek(0)
        response = HttpResponse(sio.getvalue(), content_type='application/vnd.ms-excel')
        response['Content-Disposition'] = f'attachment; filename=ab_tags_{filename_stamp}.xls'
        _log_event(request, 'front_tag_export', username=u.username, count=len(rows))
        return response

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    for tag in rows:
        profile = profile_map.get(tag.profile_guid)
        writer.writerow([
            tag.tag_name,
            tag.tag_color,
            profile.name if profile else '',
            tag.profile_guid,
            profile.owner.username if profile and profile.owner else '-',
        ])
    response = HttpResponse(output.getvalue(), content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = f'attachment; filename=ab_tags_{filename_stamp}.csv'
    _log_event(request, 'front_tag_export', username=u.username, count=len(rows))
    return response


@login_required(login_url='/api/user_action?action=login')
def ab_dashboard(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect('/api/user_action?action=login')

    profiles_qs = _ab_accessible_profiles(u, None).select_related('owner')
    profiles = list(profiles_qs)
    allowed_guids = {p.guid for p in profiles}

    total_books = len(profiles)
    total_peers = 0
    total_tags = 0
    profile_stats = []
    for profile in profiles:
        peers_count = RustDeskPeer.objects.filter(Q(uid=profile.owner_id) & Q(profile_guid=profile.guid)).count()
        tags_count = RustDeskTag.objects.filter(Q(uid=profile.owner_id) & Q(profile_guid=profile.guid)).count()
        total_peers += peers_count
        total_tags += tags_count
        profile_stats.append({
            'name': profile.name,
            'guid': profile.guid,
            'owner': profile.owner.username if profile.owner else '-',
            'peers': peers_count,
            'tags': tags_count,
        })
    profile_stats.sort(key=lambda x: x['peers'], reverse=True)
    top_profiles = profile_stats[:6]
    max_peers = max([p['peers'] for p in top_profiles], default=1)
    for p in top_profiles:
        p['peers_pct'] = int((p['peers'] / max_peers) * 100) if max_peers else 0

    shares_qs = AddressBookShare.objects.exclude(profile__guid__startswith='personal-')
    rules_qs = AddressBookRule.objects.exclude(profile__guid__startswith='personal-')
    if not u.is_admin:
        shares_qs = shares_qs.filter(Q(profile__guid__in=allowed_guids))
        rules_qs = rules_qs.filter(Q(profile__guid__in=allowed_guids))
    total_shares = shares_qs.count()
    total_rules = rules_qs.count()

    rule_stats = _summarize_rules(_collect_global_rules(None, allowed_guids if not u.is_admin else None))

    _log_event(request, 'front_ab_dashboard_view', username=u.username, total=total_books)
    return render(
        request,
        'ab_dashboard.html',
        {
            'u': u,
            'total_books': total_books,
            'total_peers': total_peers,
            'total_tags': total_tags,
            'total_shares': total_shares,
            'total_rules': total_rules,
            'top_profiles': top_profiles,
            'rule_stats': rule_stats,
            'nav_active': 'ab_dashboard',
        },
    )


@login_required(login_url='/api/user_action?action=login')
def ab_rules(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect('/api/user_action?action=login')
    if not u.is_admin:
        _log_event(request, 'front_ab_rules_denied', level="warning", username=u.username)
        return HttpResponseRedirect('/api/home')

    filter_q = str(request.GET.get('q', '')).strip()

    if request.method == 'POST':
        action = request.POST.get('action', '')
        redirect_params = {}
        if filter_q:
            redirect_params['q'] = filter_q
        redirect_url = '/api/ab_rules'
        if redirect_params:
            redirect_url = f"{redirect_url}?{urlencode(redirect_params)}"

        if action in ('update_rule', 'delete_rule'):
            rule_value = _parse_rule(request.POST.get('rule', 1))
            rule_guid = request.POST.get('rule_guid', '')
            if not rule_guid:
                messages.error(request, _('规则不存在。'))
                return HttpResponseRedirect(redirect_url)
            ok, msg = _apply_rule_change(request, u, action, rule_guid, rule_value)
            if ok:
                messages.success(request, msg)
            else:
                messages.error(request, msg)
            return HttpResponseRedirect(redirect_url)

        if action in ('bulk_update', 'bulk_delete'):
            selected = request.POST.getlist('selected')
            if not selected:
                messages.error(request, _('请选择至少一条规则。'))
                return HttpResponseRedirect(redirect_url)
            rule_value = _parse_rule(request.POST.get('rule', 1))
            success = 0
            failed = 0
            for guid in selected:
                if action == 'bulk_delete':
                    ok, _msg = _apply_rule_change(request, u, 'delete_rule', guid, rule_value, {'bulk': True})
                else:
                    ok, _msg = _apply_rule_change(request, u, 'update_rule', guid, rule_value, {'bulk': True})
                if ok:
                    success += 1
                else:
                    failed += 1
            if action == 'bulk_delete':
                messages.success(request, _('已批量删除 %(count)s 条规则。') % {'count': success})
            else:
                messages.success(request, _('已批量更新 %(count)s 条规则。') % {'count': success})
            if failed:
                messages.warning(request, _('有 %(count)s 条规则未能处理。') % {'count': failed})
            return HttpResponseRedirect(redirect_url)

    try:
        rules = _collect_global_rules(filter_q)
        rule_stats = _summarize_rules(rules)
        paginator = Paginator(rules, 20)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)
    except Exception as exc:
        logger.exception("ab_rules view failed: %s", exc)
        messages.error(request, _('规则总览加载失败，请检查数据库迁移与日志输出。'))
        return HttpResponseRedirect('/api/ab_manage')

    _log_event(request, 'front_ab_rules_view', username=u.username, total=page_obj.paginator.count)
    return render(
        request,
        'ab_rules.html',
        {
            'u': u,
            'page_obj': page_obj,
            'rule_stats': rule_stats,
            'filter_q': filter_q,
            'rule_choices': [
                (1, _('只读')),
                (2, _('读写')),
                (3, _('完全控制')),
            ],
            'nav_active': 'ab_rules',
        },
    )


@login_required(login_url='/api/user_action?action=login')
def ab_rules_export(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect('/api/user_action?action=login')
    if not u.is_admin:
        _log_event(request, 'front_ab_rules_export_denied', level="warning", username=u.username)
        return HttpResponseRedirect('/api/home')

    export_format = str(request.GET.get('format', 'csv')).lower()
    filter_q = str(request.GET.get('q', '')).strip()
    rules = _collect_global_rules(filter_q)
    filename_stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M')

    if export_format in ('xls', 'xlsx'):
        workbook = xlwt.Workbook(encoding='utf-8')
        sheet = workbook.add_sheet(_('地址簿规则'), cell_overwrite_ok=True)
        headers = [_('地址簿'), _('地址簿 GUID'), _('所属用户'), _('类型'), _('目标'), _('权限')]
        for col, header in enumerate(headers):
            sheet.write(0, col, header)
        for row, entry in enumerate(rules, start=1):
            sheet.write(row, 0, entry.get('profile_name', ''))
            sheet.write(row, 1, entry.get('profile_guid', ''))
            sheet.write(row, 2, entry.get('owner', ''))
            sheet.write(row, 3, entry.get('target_type', ''))
            sheet.write(row, 4, entry.get('target_name', ''))
            sheet.write(row, 5, entry.get('rule_label', ''))
        sio = BytesIO()
        workbook.save(sio)
        sio.seek(0)
        response = HttpResponse(sio.getvalue(), content_type='application/vnd.ms-excel')
        response['Content-Disposition'] = f'attachment; filename=ab_rules_{filename_stamp}.xls'
        return response

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow([_('地址簿'), _('地址簿 GUID'), _('所属用户'), _('类型'), _('目标'), _('权限')])
    for entry in rules:
        writer.writerow([
            entry.get('profile_name', ''),
            entry.get('profile_guid', ''),
            entry.get('owner', ''),
            entry.get('target_type', ''),
            entry.get('target_name', ''),
            entry.get('rule_label', ''),
        ])
    response = HttpResponse(output.getvalue(), content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = f'attachment; filename=ab_rules_{filename_stamp}.csv'
    return response


@login_required(login_url='/api/user_action?action=login')
def ab_shares_export(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect('/api/user_action?action=login')
    export_format = str(request.GET.get('format', 'csv')).lower()
    filter_q = str(request.GET.get('q', '')).strip()

    shares = AddressBookShare.objects.select_related('profile', 'user', 'profile__owner').exclude(profile__guid__startswith='personal-')
    if not u.is_admin:
        shares = shares.filter(Q(profile__owner=u))
    if filter_q:
        shares = shares.filter(
            Q(profile__name__icontains=filter_q)
            | Q(profile__guid__icontains=filter_q)
            | Q(profile__owner__username__icontains=filter_q)
            | Q(user__username__icontains=filter_q)
        )
    rows = list(shares.order_by('profile__name'))
    filename_stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M')

    headers = [_('地址簿'), _('地址簿 GUID'), _('所属用户'), _('共享给用户'), _('权限'), _('创建时间')]
    if export_format in ('xls', 'xlsx'):
        workbook = xlwt.Workbook(encoding='utf-8')
        sheet = workbook.add_sheet(_('地址簿共享列表'), cell_overwrite_ok=True)
        for col, header in enumerate(headers):
            sheet.write(0, col, header)
        for row, share in enumerate(rows, start=1):
            profile = share.profile
            sheet.write(row, 0, profile.name if profile else '')
            sheet.write(row, 1, profile.guid if profile else '')
            sheet.write(row, 2, profile.owner.username if profile and profile.owner else '-')
            sheet.write(row, 3, share.user.username if share.user else '-')
            sheet.write(row, 4, _rule_label(share.rule))
            sheet.write(row, 5, share.created_at.strftime('%Y-%m-%d %H:%M') if share.created_at else '')
        sio = BytesIO()
        workbook.save(sio)
        sio.seek(0)
        response = HttpResponse(sio.getvalue(), content_type='application/vnd.ms-excel')
        response['Content-Disposition'] = f'attachment; filename=ab_shares_{filename_stamp}.xls'
        _log_event(request, 'front_ab_shares_export', username=u.username, count=len(rows))
        return response

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    for share in rows:
        profile = share.profile
        writer.writerow([
            profile.name if profile else '',
            profile.guid if profile else '',
            profile.owner.username if profile and profile.owner else '-',
            share.user.username if share.user else '-',
            _rule_label(share.rule),
            share.created_at.strftime('%Y-%m-%d %H:%M') if share.created_at else '',
        ])
    response = HttpResponse(output.getvalue(), content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = f'attachment; filename=ab_shares_{filename_stamp}.csv'
    _log_event(request, 'front_ab_shares_export', username=u.username, count=len(rows))
    return response


@login_required(login_url='/api/user_action?action=login')
def ab_audit(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect('/api/user_action?action=login')
    if not u.is_admin:
        _log_event(request, 'front_ab_audit_denied', level="warning", username=u.username)
        return HttpResponseRedirect('/api/home')

    filter_q = str(request.GET.get('q', '')).strip()
    audits = AddressBookRuleAudit.objects.select_related('profile', 'actor').order_by('-created_at')
    if filter_q:
        audits = audits.filter(
            Q(profile__name__icontains=filter_q)
            | Q(profile__guid__icontains=filter_q)
            | Q(actor__username__icontains=filter_q)
            | Q(target_name__icontains=filter_q)
            | Q(action__icontains=filter_q)
        )
    paginator = Paginator(audits, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    _log_event(request, 'front_ab_audit_view', username=u.username, total=page_obj.paginator.count)

    action_labels = {
        'share_add': _('用户共享新增'),
        'share_update': _('用户共享更新'),
        'share_delete': _('用户共享删除'),
        'rule_add': _('规则新增'),
        'rule_update': _('规则更新'),
        'rule_delete': _('规则删除'),
    }

    entries = []
    for audit in page_obj:
        entries.append({
            'created_at': audit.created_at,
            'profile_name': audit.profile.name if audit.profile else '-',
            'profile_guid': audit.profile.guid if audit.profile else '-',
            'actor': audit.actor.username if audit.actor else '-',
            'action': action_labels.get(audit.action, audit.action),
            'target_type': _rule_target_label(audit.target_type),
            'target_name': audit.target_name or '-',
            'rule_label': _rule_label(audit.rule),
            'details': audit.details or '',
        })

    return render(
        request,
        'ab_audit.html',
        {
            'u': u,
            'page_obj': page_obj,
            'entries': entries,
            'filter_q': filter_q,
            'nav_active': 'ab_audit',
        },
    )


def get_conn_log():
    logs = ConnLog.objects.all()
    logs = {x.id: model_to_dict(x) for x in logs}

    for k, v in logs.items():
        try:
            peer = RustDeskPeer.objects.get(rid=v['rid'])
            logs[k]['alias'] = peer.alias
        except: # noqa
            logs[k]['alias'] = _('UNKNOWN')
        try:
            peer = RustDeskPeer.objects.get(rid=v['from_id'])
            logs[k]['from_alias'] = peer.alias
        except: # noqa
            logs[k]['from_alias'] = _('UNKNOWN')
        # from_zone = tz.tzutc()
        # to_zone = tz.tzlocal()
        # utc = logs[k]['logged_at']
        # utc = utc.replace(tzinfo=from_zone)
        # logs[k]['logged_at'] = utc.astimezone(to_zone)
        try:
            duration = round((logs[k]['conn_end'] - logs[k]['conn_start']).total_seconds())
            m, s = divmod(duration, 60)
            h, m = divmod(m, 60)
            # d, h = divmod(h, 24)
            logs[k]['duration'] = f'{h:02d}:{m:02d}:{s:02d}'
        except:   # noqa
            logs[k]['duration'] = -1

    sorted_logs = sorted(logs.items(), key=lambda x: x[1]['conn_start'], reverse=True)
    new_ordered_dict = {}
    for key, alog in sorted_logs:
        new_ordered_dict[key] = alog

    return [v for k, v in new_ordered_dict.items()]


def get_file_log():
    logs = FileLog.objects.all()
    logs = {x.id: model_to_dict(x) for x in logs}

    for k, v in logs.items():
        try:
            peer_remote = RustDeskPeer.objects.get(rid=v['remote_id'])
            logs[k]['remote_alias'] = peer_remote.alias
        except:   # noqa
            logs[k]['remote_alias'] = _('UNKNOWN')
        try:
            peer_user = RustDeskPeer.objects.get(rid=v['user_id'])
            logs[k]['user_alias'] = peer_user.alias
        except:   # noqa
            logs[k]['user_alias'] = _('UNKNOWN')

    sorted_logs = sorted(logs.items(), key=lambda x: x[1]['logged_at'], reverse=True)
    new_ordered_dict = {}
    for key, alog in sorted_logs:
        new_ordered_dict[key] = alog

    return [v for k, v in new_ordered_dict.items()]


@login_required(login_url='/api/user_action?action=login')
def conn_log(request):
    if not request.user.is_admin:
        _log_event(request, 'front_conn_log_denied', level="warning", username=request.user.username)
        return HttpResponseRedirect('/api/home')
    paginator = Paginator(get_conn_log(), 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    _log_event(request, 'front_conn_log_view', username=request.user.username, page=page_number)
    return render(
        request,
        'show_conn_log.html',
        {'page_obj': page_obj, 'u': request.user, 'nav_active': 'conn_log'},
    )


@login_required(login_url='/api/user_action?action=login')
def file_log(request):
    if not request.user.is_admin:
        _log_event(request, 'front_file_log_denied', level="warning", username=request.user.username)
        return HttpResponseRedirect('/api/home')
    paginator = Paginator(get_file_log(), 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    _log_event(request, 'front_file_log_view', username=request.user.username, page=page_number)
    return render(
        request,
        'show_file_log.html',
        {'page_obj': page_obj, 'u': request.user, 'nav_active': 'file_log'},
    )
