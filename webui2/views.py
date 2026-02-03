from django.conf import settings as _settings
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone


@login_required(login_url='/api/user_action?action=login')
def index(request):
    if _settings.ID_SERVER == '':
        _settings.ID_SERVER = request.get_host().split(":")[0]
    context = {
        "domain": _settings.ID_SERVER or request.get_host().split(":")[0],
    }
    return render(request, 'webui2.html', context)


@login_required(login_url='/api/user_action?action=login')
def status(request):
    host = request.get_host().split(":")[0]
    if _settings.ID_SERVER == '':
        _settings.ID_SERVER = host
    return JsonResponse({
        "id_server": _settings.ID_SERVER or host,
        "host": host,
        "user": request.user.username or "",
        "is_admin": bool(getattr(request.user, "is_admin", False)),
        "server_time": timezone.now().isoformat(),
    })
