import django
if django.__version__.split('.')[0]>='4':
    from django.urls import re_path as url
else:
    from django.conf.urls import  url, include

from api import views_api, views_front

urlpatterns = [
    url(r'^login-options$', views_api.login_options),
    url(r'^oidc/auth$', views_api.oidc_auth),
    url(r'^oidc/auth-query$', views_api.oidc_auth_query),
    url(r'^login$', views_api.login),
    url(r'^logout$', views_api.logout),
    url(r'^currentUser$', views_api.currentUser),
    url(r'^sysinfo_ver$', views_api.sysinfo_ver),
    url(r'^sysinfo$', views_api.sysinfo),
    url(r'^heartbeat$', views_api.heartbeat),
    url(r'^record$', views_api.record),
    url(r'^devices/cli$', views_api.devices_cli),
    url(r'^audit/(?P<typ>.+)$', views_api.audit_with_type),
    url(r'^audit$', views_api.audit_root),

    url(r'^ab/settings$', views_api.ab_settings),
    url(r'^ab/personal$', views_api.ab_personal),
    url(r'^ab/shared/profiles$', views_api.ab_shared_profiles),
    url(r'^ab/shared/add$', views_api.ab_shared_add),
    url(r'^ab/shared/update/profile$', views_api.ab_shared_update_profile),
    url(r'^ab/shared$', views_api.ab_shared_delete),
    url(r'^ab/peers$', views_api.ab_peers),
    url(r'^ab/tags/(?P<guid>[^/]+)$', views_api.ab_tags),
    url(r'^ab/peer/add/(?P<guid>[^/]+)$', views_api.ab_peer_add),
    url(r'^ab/peer/update/(?P<guid>[^/]+)$', views_api.ab_peer_update),
    url(r'^ab/peer/(?P<guid>[^/]+)$', views_api.ab_peer_delete),
    url(r'^ab/tag/add/(?P<guid>[^/]+)$', views_api.ab_tag_add),
    url(r'^ab/tag/rename/(?P<guid>[^/]+)$', views_api.ab_tag_rename),
    url(r'^ab/tag/update/(?P<guid>[^/]+)$', views_api.ab_tag_update),
    url(r'^ab/tag/(?P<guid>[^/]+)$', views_api.ab_tag_delete),
    url(r'^ab/rules$', views_api.ab_rules),
    url(r'^ab/rule$', views_api.ab_rule),
    url(r'^ab/get$', views_api.ab_get), # 兼容 x86-sciter 版客户端
    url(r'^ab$', views_api.ab),

    url(r'^device-group/accessible$', views_api.device_group_accessible),
    url(r'^users$', views_api.users),
    url(r'^peers$', views_api.peers),

    #url(r'^register',views.register),
    url(r'^user_action', views_front.user_action),  # 前端
    url(r'^home', views_front.home),                # 前端
    url(r'^work', views_front.work),                # 前端
    url(r'^ab_dashboard', views_front.ab_dashboard),# 前端
    url(r'^ab_books', views_front.ab_books),        # 前端
    url(r'^ab_book', views_front.ab_book),          # 前端
    url(r'^ab_books_export', views_front.ab_books_export),  # 前端
    url(r'^ab_book_export', views_front.ab_book_export),    # 前端
    url(r'^tag_manage', views_front.tag_manage),    # 前端
    url(r'^tag_export', views_front.tag_export),    # 前端
    url(r'^ab_manage', views_front.ab_manage),      # 前端
    url(r'^ab_rules_export', views_front.ab_rules_export),  # 前端
    url(r'^ab_shares_export', views_front.ab_shares_export),# 前端
    url(r'^ab_rules', views_front.ab_rules),        # 前端
    url(r'^ab_audit', views_front.ab_audit),        # 前端
    url(r'^down_peers$', views_front.down_peers),   # 前端
    url(r'^share', views_front.share),              # 前端
    url(r'^conn_log', views_front.conn_log),
    url(r'^file_log', views_front.file_log),
]
