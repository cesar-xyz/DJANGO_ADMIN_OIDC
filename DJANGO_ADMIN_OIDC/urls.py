"""
URL configuration for DJANGO_ADMIN_KEYCLOAK project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from .views import keycloak_callback, keycloak_login, login_error, custom_login_view, custom_logout

admin.site.login = custom_login_view

urlpatterns = [
    path("dadmin/", admin.site.urls),
    path("logout/", custom_logout, name='custom_logout'),
    path("dadmin/login/", custom_login_view, name='custom_login'),
    path('login/', keycloak_login, name='login'),
    path('login/callback/', keycloak_callback),
    path('login/error/', login_error, name='login_error'),
    path('oidc/', include('allauth.urls')),
]
