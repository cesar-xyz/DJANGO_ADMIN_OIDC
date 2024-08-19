# Django Admin Keycloak Library

A Python library to integrate OpenID Connect (OIDC) using Keycloak authentication with Django's admin interface. This library provides
customizable tools to add OIDC-based authentication to Django projects.

## Features

- Seamless integration with OIDC providers.
- Custom authentication backends for Django.
- Extendable and easy to configure.

## Installation

To install the library, use pip:

```bash
pip install django-admin-oidc
```

## Usage

### 1. Add to Installed Apps

Include the library in your Django project by adding it to the `INSTALLED_APPS` in your `settings.py`:

```python
INSTALLED_APPS = [
    ...,
    'django_admin_oidc',
]
```

### 2. Configure OIDC Settings

Set up the OIDC configuration in your Django `settings.py` file. Here is an example configuration:

```python
OIDC_RP_CLIENT_ID = 'your-client-id'
OIDC_RP_CLIENT_SECRET = 'your-client-secret'
OIDC_OP_AUTHORIZATION_ENDPOINT = 'https://your-oidc-provider.com/auth'
OIDC_OP_TOKEN_ENDPOINT = 'https://your-oidc-provider.com/token'
OIDC_OP_USER_ENDPOINT = 'https://your-oidc-provider.com/userinfo'

AUTHENTICATION_BACKENDS = [
    'django_admin_oidc.authentication.YourCustomOIDCBackend',
    'django.contrib.auth.backends.ModelBackend',
]
```

### 3. Update URLs

Update your `urls.py` to include the necessary OIDC routes:

```python
from django.urls import path, include

urlpatterns = [
    ...,
    path('oidc/', include('django_admin_oidc.urls')),
]
```
# DJANGO_ADMIN_OIDC
