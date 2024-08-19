from urllib.parse import urlencode

import requests
from django.conf import settings
from django.contrib.auth import login, authenticate, logout
from django.shortcuts import redirect, render
from django.urls import reverse

from authentication import KeycloakOIDCBackend


def custom_logout(request):
    logout_url = settings.LOGOUT_REDIRECT_URL
    logout(request)
    return redirect(logout_url)


def custom_login_view(request):
    show_login_form = settings.OIDC_LOGIN or False
    logout_url = settings.LOGOUT_REDIRECT_URL
    if request.user.is_authenticated:
        # logout(request)
        return render(request, 'admin/login.html', {
            'show_login_form': show_login_form,
            'logout': logout_url,
            'username': request.user,
        })
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect(reverse('admin:index'))
        else:
            # logout(request)
            return render(request, 'admin/login.html', {
                'show_login_form': show_login_form,
                'logout': logout_url,
                'username': request.user,
                'error_message': 'Nombre de usuario o contraseña inválidos.',
            })

    return render(request, 'admin/login.html', {
        'app_path': reverse('admin:login'),
        'show_login_form': show_login_form,
        'username': request.user,
        'logout': logout_url,
    })


def keycloak_login(request):
    base_url = f'https://{settings.ID_BASE_URL}/realms/{settings.OIDC_REALM}/protocol/openid-connect/auth'
    params = {
        'client_id': settings.OIDC_RP_CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': request.build_absolute_uri('/login/callback/'),
        'scope': 'openid profile email',
    }
    url = f"{base_url}?{urlencode(params)}"
    return redirect(url)


def keycloak_callback(request):
    code = request.GET.get('code')
    if not code:
        return handle_error(request, "Código de autorización no encontrado.")

    token_url = f"https://{settings.ID_BASE_URL}/realms/{settings.OIDC_REALM}/protocol/openid-connect/token"
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': request.build_absolute_uri('/login/callback/'),
        'client_id': settings.OIDC_RP_CLIENT_ID,
        'client_secret': settings.OIDC_RP_CLIENT_SECRET,
    }

    try:
        response = requests.post(token_url, data=data)
        response.raise_for_status()
        token_data = response.json()
    except requests.exceptions.RequestException as e:
        return handle_error(request, f"Error de conexión al servidor de autenticación: {e}")
    except ValueError:
        return handle_error(request, "Respuesta no válida del servidor de autenticación.")

    access_token = token_data.get('access_token')
    if not access_token:
        return handle_error(request, f"Error al solicitar el token: {response.status_code}")

    request.session['access_token'] = access_token

    backend = KeycloakOIDCBackend()
    user, auth = backend.authenticate(request=request, token=access_token)

    if user:
        user.backend = f'{backend.__module__}.{backend.__class__.__name__}'
        login(request, user)
        return redirect('/dadmin')
    else:
        return handle_error(request, "Autenticación fallida.")


def handle_error(request, error_message):
    request.session['error_message'] = error_message
    return redirect('login_error')


def login_error(request):
    error_message = request.session.pop('error_message', '')
    context = {
        'error_message': error_message
    }
    return render(request, 'login_error.html', context)
