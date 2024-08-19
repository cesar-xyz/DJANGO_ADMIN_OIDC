import os

import jwt
import requests
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from rest_framework import authentication, exceptions

User = get_user_model()


def _introspect_token(token):
    id_base_url = os.getenv('ID_BASE_URL')
    realm = os.getenv('OIDC_REALM')
    introspection_endpoint = f'https://{id_base_url}/realms/{realm}/protocol/openid-connect/token/introspect'

    response = requests.post(introspection_endpoint, data={
        'token': token,
        'client_id': os.getenv('OIDC_RP_CLIENT_ID'),
        'client_secret': os.getenv('OIDC_RP_CLIENT_SECRET'),
    })
    print(response, os.getenv('OIDC_RP_CLIENT_SECRET'))
    if response.status_code == 200:
        result = response.json()
        return result.get('active', False)
    return False


def _assign_user_groups(user, roles):
    relevant_roles = [role for role in roles if role not in ['superuser', 'staff']]

    current_groups = user.groups.all()
    for group in current_groups:
        if group.name not in relevant_roles:
            user.groups.remove(group)

    for role in relevant_roles:
        group, created = Group.objects.get_or_create(name=role)
        user.groups.add(group)


class KeycloakOIDCBackend(authentication.BaseAuthentication):

    def authenticate(self, request, token=None, **kwargs):
        try:
            token = request.META.get('HTTP_AUTHORIZATION') or request.META.get('HTTP_BEARER') or token
        except UnicodeError:
            msg = 'Invalid token header. Token string should not contain invalid characters.'
            raise exceptions.AuthenticationFailed(msg)
        if _introspect_token(token):
            return self.get_or_create_user(request, token)

        return None

    def get_or_create_user(self, request, token):
        try:
            user_info = self.fetch_user_info(token)

            if not user_info:
                raise exceptions.AuthenticationFailed('Failed to fetch user information.')

            user = self.create_user(user_info)

            if user:
                return user, None
            else:
                raise exceptions.AuthenticationFailed('Failed to create user.')

        except Exception as e:
            raise exceptions.AuthenticationFailed(f'Authentication error: {str(e)}')

    def fetch_user_info(self, token):
        try:
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            resource_access = decoded_token.get('resource_access', {})
            resource = resource_access.get(os.getenv('OIDC_RP_CLIENT_ID'), {})
            roles = resource.get('roles', [])
            user_info = {
                'sub': decoded_token.get('preferred_username', ''),
                'email': decoded_token.get('email', ''),
                'given_name': decoded_token.get('given_name', ''),
                'last_name': decoded_token.get('family_name', ''),
                'roles': roles,
            }
            return user_info if user_info['sub'] and user_info['email'] else None
        except Exception as err:
            raise exceptions.AuthenticationFailed(f'Error decoding token: {err}')

    def create_user(self, user_info):
        try:
            existing_user = User.objects.filter(email=user_info['email']).first()

            is_superuser = 'superuser' in user_info['roles']
            is_staff = 'staff' in user_info['roles'] or is_superuser

            if existing_user:
                if existing_user.is_superuser != is_superuser or existing_user.is_staff != is_staff:
                    existing_user.is_superuser = is_superuser
                    existing_user.is_staff = is_staff
                    existing_user.save()
                _assign_user_groups(existing_user, user_info['roles'])
                return existing_user

            user, created = User.objects.get_or_create(
                username=user_info['sub'],
                defaults={
                    'email': user_info['email'],
                    'first_name': user_info.get('given_name', ''),
                    'last_name': user_info.get('last_name', ''),
                }
            )

            if created:
                user.set_unusable_password()

                if user.is_superuser != is_superuser or user.is_staff != is_staff:
                    user.is_superuser = is_superuser
                    user.is_staff = is_staff

                user.save()

                _assign_user_groups(user, user_info['roles'])
            return user
        except Exception as e:
            raise exceptions.AuthenticationFailed(f'User creation error: {str(e)}')

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
