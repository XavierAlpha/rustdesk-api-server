# cython:language_level=3
import uuid
from django.db import models
from django.contrib import admin
from django.contrib.auth.models import Group
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from django.utils import timezone


class RustDeskToken(models.Model):
    ''' Token
    '''
    username = models.CharField(verbose_name=_('用户名'), max_length=20)
    rid = models.CharField(verbose_name=_('Camellia ID'), max_length=16)
    uid = models.CharField(verbose_name=_('用户ID'), max_length=16)
    uuid = models.CharField(verbose_name=_('uuid'), max_length=60)
    access_token = models.CharField(verbose_name=_('access_token'), max_length=60, blank=True)
    create_time = models.DateTimeField(verbose_name=_('登录时间'), auto_now_add=True)
    expires_at = models.DateTimeField(verbose_name=_('过期时间'), null=True, blank=True, db_index=True)
    # expire_time = models.DateTimeField(verbose_name='过期时间')

    class Meta:
        ordering = ('-username',)
        verbose_name = _("令牌")
        verbose_name_plural = _("令牌列表")


class RustDeskTokenAdmin(admin.ModelAdmin):
    list_display = ('username', 'uid', 'expires_at')
    search_fields = ('username', 'uid')
    list_filter = ('create_time', 'expires_at')  # 过滤器


class RustDeskTag(models.Model):
    ''' Tags
    '''
    uid = models.CharField(verbose_name=_('所属用户ID'), max_length=16)
    tag_name = models.CharField(verbose_name=_('标签名称'), max_length=60)
    tag_color = models.CharField(verbose_name=_('标签颜色'), max_length=60, blank=True)
    profile_guid = models.CharField(verbose_name=_('地址簿GUID'), max_length=60, blank=True, db_index=True)

    class Meta:
        ordering = ('-uid',)
        verbose_name = _("标签")
        verbose_name_plural = _("标签列表")


class RustDeskTagAdmin(admin.ModelAdmin):
    list_display = ('tag_name', 'uid', 'profile_guid', 'tag_color')
    search_fields = ('tag_name', 'uid', 'profile_guid')
    list_filter = ('uid', 'profile_guid')


class RustDeskPeer(models.Model):
    ''' Pees
    '''
    uid = models.CharField(verbose_name=_('用户ID'), max_length=16)
    rid = models.CharField(verbose_name=_('客户端ID'), max_length=60)
    username = models.CharField(verbose_name=_('系统用户名'), max_length=20)
    hostname = models.CharField(verbose_name=_('操作系统名'), max_length=30)
    alias = models.CharField(verbose_name=_('别名'), max_length=30)
    platform = models.CharField(verbose_name=_('平台'), max_length=30)
    tags = models.CharField(verbose_name=_('标签'), max_length=30)
    rhash = models.CharField(verbose_name=_('设备链接密码'), max_length=60)
    note = models.TextField(verbose_name=_('备注'), blank=True, default='')
    password = models.CharField(verbose_name=_('共享密码'), max_length=60, blank=True, default='')
    device_group_name = models.CharField(verbose_name=_('设备组'), max_length=60, blank=True, default='')
    login_name = models.CharField(verbose_name=_('登录账号'), max_length=60, blank=True, default='')
    same_server = models.BooleanField(verbose_name=_('同服务器'), default=False)
    profile_guid = models.CharField(verbose_name=_('地址簿GUID'), max_length=60, blank=True, db_index=True)

    class Meta:
        ordering = ('-username',)
        verbose_name = _("客户端")
        verbose_name_plural = _("客户端列表")


class RustDeskPeerAdmin(admin.ModelAdmin):
    list_display = ('rid', 'uid', 'username', 'hostname', 'platform', 'alias', 'tags', 'profile_guid')
    search_fields = ('rid', 'alias', 'profile_guid')
    list_filter = ('rid', 'uid', 'profile_guid')


class RustDesDevice(models.Model):
    rid = models.CharField(verbose_name=_('客户端ID'), max_length=60, blank=True)
    cpu = models.CharField(verbose_name='CPU', max_length=100)
    hostname = models.CharField(verbose_name=_('主机名'), max_length=100)
    memory = models.CharField(verbose_name=_('内存'), max_length=100)
    os = models.CharField(verbose_name=_('操作系统'), max_length=100)
    uuid = models.CharField(verbose_name='uuid', max_length=100)
    username = models.CharField(verbose_name=_('系统用户名'), max_length=100, blank=True)
    version = models.CharField(verbose_name=_('客户端版本'), max_length=100)
    ip_address = models.CharField(verbose_name=_('IP'), max_length=60, blank=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name='devices')
    owner_name = models.CharField(verbose_name=_('归属用户'), max_length=60, blank=True, default='')
    device_group_name = models.CharField(verbose_name=_('设备组'), max_length=60, blank=True, default='')
    note = models.TextField(verbose_name=_('备注'), blank=True, default='')
    strategy_name = models.CharField(verbose_name=_('策略名称'), max_length=60, blank=True, default='')
    address_book_name = models.CharField(verbose_name=_('地址簿名称'), max_length=60, blank=True, default='')
    address_book_tag = models.CharField(verbose_name=_('地址簿标签'), max_length=60, blank=True, default='')
    address_book_alias = models.CharField(verbose_name=_('地址簿别名'), max_length=60, blank=True, default='')
    address_book_password = models.CharField(verbose_name=_('地址簿密码'), max_length=128, blank=True, default='')
    address_book_note = models.TextField(verbose_name=_('地址簿备注'), blank=True, default='')
    create_time = models.DateTimeField(verbose_name=_('设备注册时间'), auto_now_add=True)
    update_time = models.DateTimeField(verbose_name=('设备更新时间'), auto_now=True, blank=True)

    class Meta:
        ordering = ('-rid',)
        verbose_name = _("设备")
        verbose_name_plural = _("设备列表")


class RustDesDeviceAdmin(admin.ModelAdmin):
    list_display = ('rid', 'hostname', 'memory', 'uuid', 'version', 'owner_name', 'device_group_name', 'create_time', 'update_time')
    search_fields = ('hostname', 'memory', 'owner_name', 'device_group_name')
    list_filter = ('rid', )


class ConnLog(models.Model):
    id = models.IntegerField(verbose_name='ID', primary_key=True)
    action = models.CharField(verbose_name='Action', max_length=20, null=True)
    conn_id = models.CharField(verbose_name='Connection ID', max_length=10, null=True)
    from_ip = models.CharField(verbose_name='From IP', max_length=30, null=True)
    from_id = models.CharField(verbose_name='From ID', max_length=20, null=True)
    rid = models.CharField(verbose_name='To ID', max_length=20, null=True)
    conn_start = models.DateTimeField(verbose_name='Connected', null=True)
    conn_end = models.DateTimeField(verbose_name='Disconnected', null=True)
    session_id = models.CharField(verbose_name='Session ID', max_length=60, null=True)
    uuid = models.CharField(verbose_name='uuid', max_length=60, null=True)
    conn_type = models.IntegerField(verbose_name='Conn Type', null=True)

    class Meta:
        ordering = ('-conn_start',)
        verbose_name = _("连接日志")
        verbose_name_plural = _("连接日志列表")


class ConnLogAdmin(admin.ModelAdmin):
    list_display = ('id', 'action', 'conn_id', 'from_ip', 'from_id', 'rid', 'conn_type', 'conn_start', 'conn_end', 'session_id', 'uuid')
    search_fields = ('from_ip', 'rid')
    list_filter = ('id', 'from_ip', 'from_id', 'rid', 'conn_start', 'conn_end')


class FileLog(models.Model):
    id = models.IntegerField(verbose_name='ID', primary_key=True)
    file = models.CharField(verbose_name='Path', max_length=500)
    remote_id = models.CharField(verbose_name='Remote ID', max_length=20, default='0')
    user_id = models.CharField(verbose_name='User ID', max_length=20, default='0')
    user_ip = models.CharField(verbose_name='User IP', max_length=20, default='0')
    filesize = models.CharField(verbose_name='Filesize', max_length=500, default='')
    direction = models.IntegerField(verbose_name='Direction', default=0)
    logged_at = models.DateTimeField(verbose_name='Logged At', null=True)

    class Meta:
        ordering = ('-logged_at',)
        verbose_name = _("文件传输日志")
        verbose_name_plural = _("文件传输日志列表")


class FileLogAdmin(admin.ModelAdmin):
    list_display = ('id', 'file', 'remote_id', 'user_id', 'user_ip', 'filesize', 'direction', 'logged_at')
    search_fields = ('file', 'remote_id', 'user_id', 'user_ip')
    list_filter = ('id', 'file', 'remote_id', 'user_id', 'user_ip', 'filesize', 'direction', 'logged_at')


class ShareLink(models.Model):
    ''' 分享链接
    '''
    uid = models.CharField(verbose_name=_('用户ID'), max_length=16)
    shash = models.CharField(verbose_name=_('链接Key'), max_length=60)
    peers = models.CharField(verbose_name=_('机器ID列表'), max_length=20)
    is_used = models.BooleanField(verbose_name=_('是否使用'), default=False)
    is_expired = models.BooleanField(verbose_name=_('是否过期'), default=False)
    create_time = models.DateTimeField(verbose_name=_('生成时间'), auto_now_add=True)

    class Meta:
        ordering = ('-create_time',)
        verbose_name = _("分享链接")
        verbose_name_plural = _("链接列表")


class StrategyProfile(models.Model):
    name = models.CharField(verbose_name=_('策略名称'), max_length=60, unique=True)
    config_options = models.TextField(verbose_name=_('配置项'), blank=True, default='')
    updated_at = models.DateTimeField(verbose_name=_('更新时间'), auto_now=True)

    class Meta:
        ordering = ('name',)
        verbose_name = _("策略")
        verbose_name_plural = _("策略列表")

    def __str__(self):
        return self.name or f"Strategy {self.pk}"


class AddressBookProfile(models.Model):
    guid = models.CharField(verbose_name=_('地址簿GUID'), max_length=60, unique=True)
    name = models.CharField(verbose_name=_('地址簿名称'), max_length=60)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='address_book_profiles')
    note = models.TextField(verbose_name=_('备注'), blank=True, default='')
    rule = models.IntegerField(verbose_name=_('共享权限'), default=1)
    info = models.TextField(verbose_name=_('扩展信息'), blank=True, default='')
    created_at = models.DateTimeField(verbose_name=_('创建时间'), default=timezone.now)
    updated_at = models.DateTimeField(verbose_name=_('更新时间'), auto_now=True)

    class Meta:
        ordering = ('name',)
        verbose_name = _("地址簿")
        verbose_name_plural = _("地址簿列表")

    def __str__(self):
        owner = getattr(self.owner, "username", "") or self.owner_id or "-"
        return f"{self.name} ({owner})"


class AddressBookShare(models.Model):
    guid = models.CharField(max_length=64, unique=True, default=uuid.uuid4, editable=False)
    profile = models.ForeignKey(AddressBookProfile, on_delete=models.CASCADE, related_name='shares')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='address_book_shares')
    rule = models.IntegerField(verbose_name=_('共享权限'), default=1)
    created_at = models.DateTimeField(verbose_name=_('创建时间'), default=timezone.now)

    class Meta:
        unique_together = ('profile', 'user')
        verbose_name = _("地址簿共享")
        verbose_name_plural = _("地址簿共享列表")

    def __str__(self):
        profile = getattr(self.profile, "name", "") or self.profile_id or "-"
        user = getattr(self.user, "username", "") or self.user_id or "-"
        return f"{profile} -> {user}"


class AddressBookRule(models.Model):
    guid = models.CharField(max_length=64, unique=True, default=uuid.uuid4, editable=False)
    profile = models.ForeignKey(AddressBookProfile, on_delete=models.CASCADE, related_name='rules')
    rule = models.IntegerField(verbose_name=_('共享权限'), default=1)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True, related_name='address_book_rules')
    group = models.ForeignKey(Group, on_delete=models.CASCADE, null=True, blank=True, related_name='address_book_rules')
    is_everyone = models.BooleanField(default=False)
    created_at = models.DateTimeField(verbose_name=_('创建时间'), default=timezone.now)
    updated_at = models.DateTimeField(verbose_name=_('更新时间'), auto_now=True)

    class Meta:
        verbose_name = _("地址簿规则")
        verbose_name_plural = _("地址簿规则列表")

    def __str__(self):
        if self.is_everyone:
            return "Everyone"
        if self.user_id:
            return getattr(self.user, "username", "") or f"User {self.user_id}"
        if self.group_id:
            return getattr(self.group, "name", "") or f"Group {self.group_id}"
        return self.guid or f"Rule {self.pk}"


class AddressBookRuleAudit(models.Model):
    profile = models.ForeignKey(AddressBookProfile, on_delete=models.CASCADE, related_name='rule_audits')
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='address_book_rule_audits')
    action = models.CharField(max_length=32)
    target_type = models.CharField(max_length=16)
    target_name = models.CharField(max_length=120, blank=True, default='')
    rule = models.IntegerField(verbose_name=_('共享权限'), default=1)
    details = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(verbose_name=_('创建时间'), default=timezone.now)

    class Meta:
        ordering = ('-created_at',)
        verbose_name = _("地址簿规则审计")
        verbose_name_plural = _("地址簿规则审计列表")

    def __str__(self):
        return f"{self.action} {self.target_type}:{self.target_name}"


class AuditSession(models.Model):
    guid = models.CharField(verbose_name='GUID', max_length=64, unique=True)
    peer_id = models.CharField(verbose_name='Peer ID', max_length=20, db_index=True)
    session_id = models.CharField(verbose_name='Session ID', max_length=60, db_index=True)
    conn_type = models.IntegerField(verbose_name='Conn Type', default=0)
    note = models.TextField(verbose_name='Note', blank=True, default='')
    created_at = models.DateTimeField(verbose_name='Created At', default=timezone.now)
    updated_at = models.DateTimeField(verbose_name='Updated At', auto_now=True)

    class Meta:
        ordering = ('-created_at',)
        verbose_name = _("审计会话")
        verbose_name_plural = _("审计会话列表")

    def __str__(self):
        return self.guid or f"Audit {self.pk}"


class AlarmLog(models.Model):
    typ = models.IntegerField(verbose_name='Type', default=0)
    info = models.TextField(verbose_name='Info', blank=True, default='')
    created_at = models.DateTimeField(verbose_name='Created At', default=timezone.now)

    class Meta:
        ordering = ('-created_at',)
        verbose_name = _("告警日志")
        verbose_name_plural = _("告警日志列表")

    def __str__(self):
        return f"Alarm {self.typ} #{self.pk}"


class ShareLinkAdmin(admin.ModelAdmin):
    list_display = ('shash', 'uid', 'peers', 'is_used', 'is_expired', 'create_time')
    search_fields = ('peers', )
    list_filter = ('is_used', 'uid', 'is_expired')
