# cython:language_level=3
from django.contrib import admin
from api import models
from django import forms
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.admin import helpers as admin_helpers
from django.contrib.auth.forms import ReadOnlyPasswordHashField
try:
    from django.contrib.auth.forms import ReadOnlyPasswordHashWidget
except Exception:  # pragma: no cover - fallback for older Django
    ReadOnlyPasswordHashWidget = None
from django.utils.translation import gettext as _


# Avoid template debug noise when admin templates probe for is_fieldset.
if not hasattr(admin_helpers.AdminReadonlyField, "is_fieldset"):
    admin_helpers.AdminReadonlyField.is_fieldset = False


class CleanReadOnlyPasswordHashWidget(ReadOnlyPasswordHashWidget if ReadOnlyPasswordHashWidget else forms.Widget):
    template_name = "auth/widgets/read_only_password_hash.html"

    def get_context(self, name, value, attrs):
        context = super().get_context(name, value, attrs)
        # Avoid template debug warnings about missing keys.
        context.setdefault("password_url", "")
        context.setdefault("button_label", _("Reset password"))
        context.setdefault("summary", [])
        return context


class UserCreationForm(forms.ModelForm):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""
    password1 = forms.CharField(label=_('密码'), widget=forms.PasswordInput)
    password2 = forms.CharField(label=_('再次输入密码'), widget=forms.PasswordInput)

    class Meta:
        model = models.UserProfile
        fields = ('username', 'email', 'note', 'is_active', 'is_admin')

    def clean_username(self):
        username = (self.cleaned_data.get("username") or "").strip()
        if not username:
            raise forms.ValidationError(_("用户名不能为空。"))
        return username

    def clean_password2(self):
        # Check that the two password entries match
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(_("密码校验失败，两次密码不一致。"))
        return password2

    
    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(UserCreationForm, self).save(commit=False)
        user.rid = user.rid or ''
        user.uuid = user.uuid or ''
        user.rtype = user.rtype or ''
        user.deviceInfo = user.deviceInfo or ''
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserChangeForm(forms.ModelForm):
    """A form for updating users. Includes all the fields on
    the user, but replaces the password field with admin's
    password hash display field.
    """
    password = ReadOnlyPasswordHashField(
        label=(_("密码Hash值")),
        help_text="",
        widget=CleanReadOnlyPasswordHashWidget(),
    )
    class Meta:
        model = models.UserProfile
        fields = ('username', 'email', 'note', 'is_active', 'is_admin')

    def clean_username(self):
        username = (self.cleaned_data.get("username") or "").strip()
        if not username:
            raise forms.ValidationError(_("用户名不能为空。"))
        return username

    def clean_password(self):
        # Regardless of what the user provides, return the initial value.
        # This is done here, rather than on the field, because the
        # field does not have access to the initial value
        return self.initial["password"]
        #return self.initial["password"]
    
    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(UserChangeForm, self).save(commit=False)
        
        if commit:
            user.save()
        return user

class UserAdmin(BaseUserAdmin):
    # The forms to add and change user instances
    form = UserChangeForm
    add_form = UserCreationForm
    password = ReadOnlyPasswordHashField(
        label=("密码Hash值"),
        help_text="",
        widget=CleanReadOnlyPasswordHashWidget(),
    )
    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    # that reference specific fields on auth.User.
    list_display = ('username', 'rid', 'email', 'is_admin', 'is_active')
    list_filter = ('is_admin', 'is_active')
    fieldsets = (
        (_('基本信息'), {'fields': ('username', 'password', 'email', 'note', 'is_active', 'is_admin', 'rid', 'uuid', 'deviceInfo',)}),
      
    )
    readonly_fields = ( 'rid', 'uuid')
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username',  'is_active', 'is_admin', 'password1', 'password2',  )}
         ),
    )
    
    search_fields = ('username', )
    ordering = ('username',)
    filter_horizontal = ()

    def save_model(self, request, obj, form, change):
        old_username = None
        if change and obj.pk:
            old = models.UserProfile.objects.filter(pk=obj.pk).only('username').first()
            old_username = getattr(old, "username", None)
        super().save_model(request, obj, form, change)
        if old_username and old_username != obj.username:
            models.RustDeskToken.objects.filter(uid=str(obj.id)).update(username=obj.username)
            models.RustDesDevice.objects.filter(owner_id=obj.id).update(owner_name=obj.username)


admin.site.register(models.UserProfile, UserAdmin)
admin.site.register(models.RustDeskToken, models.RustDeskTokenAdmin)
class RustDeskTagAdminCustom(models.RustDeskTagAdmin):
    def _remove_tag_from_peers(self, uid, profile_guid, tag_name):
        peers = models.RustDeskPeer.objects.filter(uid=str(uid), profile_guid=profile_guid)
        for peer in peers:
            tags = [x for x in peer.tags.split(',') if x and x != tag_name]
            if tags != [x for x in peer.tags.split(',') if x]:
                peer.tags = ','.join(tags)
                peer.save()

    def _rename_tag_in_peers(self, uid, profile_guid, old, new):
        peers = models.RustDeskPeer.objects.filter(uid=str(uid), profile_guid=profile_guid)
        for peer in peers:
            tags = [x for x in peer.tags.split(',') if x]
            if old in tags:
                tags = [new if x == old else x for x in tags]
                peer.tags = ','.join(tags)
                peer.save()

    def save_model(self, request, obj, form, change):
        if change and obj.pk:
            old = models.RustDeskTag.objects.filter(pk=obj.pk).first()
            if old:
                if old.profile_guid == obj.profile_guid and old.uid == obj.uid:
                    if old.tag_name != obj.tag_name:
                        self._rename_tag_in_peers(old.uid, old.profile_guid, old.tag_name, obj.tag_name)
                else:
                    self._remove_tag_from_peers(old.uid, old.profile_guid, old.tag_name)
        super().save_model(request, obj, form, change)
        duplicate = models.RustDeskTag.objects.filter(uid=obj.uid, profile_guid=obj.profile_guid, tag_name=obj.tag_name).exclude(pk=obj.pk).first()
        if duplicate:
            duplicate.delete()

    def delete_model(self, request, obj):
        self._remove_tag_from_peers(obj.uid, obj.profile_guid, obj.tag_name)
        super().delete_model(request, obj)

    def delete_queryset(self, request, queryset):
        for obj in queryset:
            self._remove_tag_from_peers(obj.uid, obj.profile_guid, obj.tag_name)
        super().delete_queryset(request, queryset)


admin.site.register(models.RustDeskTag, RustDeskTagAdminCustom)
admin.site.register(models.RustDeskPeer, models.RustDeskPeerAdmin)
admin.site.register(models.RustDesDevice, models.RustDesDeviceAdmin)
admin.site.register(models.ShareLink, models.ShareLinkAdmin)
admin.site.register(models.ConnLog, models.ConnLogAdmin)
admin.site.register(models.FileLog, models.FileLogAdmin)


class StrategyProfileAdmin(admin.ModelAdmin):
    list_display = ('name', 'updated_at')
    search_fields = ('name',)
    list_filter = ('updated_at',)


class AddressBookProfileAdmin(admin.ModelAdmin):
    list_display = ('name', 'guid', 'owner', 'rule', 'created_at', 'updated_at')
    search_fields = ('name', 'guid', 'owner__username')
    list_filter = ('rule', 'created_at', 'updated_at')

    def _cleanup_profile(self, profile):
        models.RustDeskPeer.objects.filter(uid=str(profile.owner_id), profile_guid=profile.guid).delete()
        models.RustDeskTag.objects.filter(uid=str(profile.owner_id), profile_guid=profile.guid).delete()
        models.AddressBookRule.objects.filter(profile=profile).delete()
        models.AddressBookShare.objects.filter(profile=profile).delete()

    def delete_model(self, request, obj):
        if obj:
            self._cleanup_profile(obj)
        super().delete_model(request, obj)

    def delete_queryset(self, request, queryset):
        for profile in queryset:
            self._cleanup_profile(profile)
        super().delete_queryset(request, queryset)


class AddressBookShareAdmin(admin.ModelAdmin):
    list_display = ('profile', 'user', 'rule', 'guid', 'created_at')
    search_fields = ('profile__name', 'user__username', 'guid')
    list_filter = ('rule', 'created_at')


class AuditSessionAdmin(admin.ModelAdmin):
    list_display = ('guid', 'peer_id', 'session_id', 'conn_type', 'created_at', 'updated_at')
    search_fields = ('guid', 'peer_id', 'session_id')
    list_filter = ('conn_type', 'created_at', 'updated_at')


class AlarmLogAdmin(admin.ModelAdmin):
    list_display = ('typ', 'created_at', 'info')
    search_fields = ('info',)
    list_filter = ('typ', 'created_at')


class AddressBookRuleAdmin(admin.ModelAdmin):
    list_display = ('profile', 'rule', 'user', 'group', 'is_everyone', 'guid', 'updated_at')
    search_fields = ('profile__name', 'user__username', 'group__name', 'guid')
    list_filter = ('rule', 'is_everyone', 'updated_at')


class AddressBookRuleAuditAdmin(admin.ModelAdmin):
    list_display = ('profile', 'action', 'target_type', 'target_name', 'rule', 'actor', 'created_at')
    search_fields = ('profile__name', 'target_name', 'actor__username')
    list_filter = ('action', 'target_type', 'rule', 'created_at')


admin.site.register(models.StrategyProfile, StrategyProfileAdmin)
admin.site.register(models.AddressBookProfile, AddressBookProfileAdmin)
admin.site.register(models.AddressBookShare, AddressBookShareAdmin)
admin.site.register(models.AddressBookRule, AddressBookRuleAdmin)
admin.site.register(models.AddressBookRuleAudit, AddressBookRuleAuditAdmin)
admin.site.register(models.AuditSession, AuditSessionAdmin)
admin.site.register(models.AlarmLog, AlarmLogAdmin)
admin.site.unregister(Group)
admin.site.site_header = _('Camellia 管理后台')
admin.site.site_title = _('Camellia 管理后台')
