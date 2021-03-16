import base64
from collections import namedtuple

from aiohttp import web, web_request
from aiohttp.web_exceptions import HTTPUnauthorized, HTTPForbidden
from aiohttp_security import SessionIdentityPolicy, check_permission, remember, forget
from aiohttp_security import setup as setup_security
from aiohttp_security.abc import AbstractAuthorizationPolicy
from aiohttp_session import setup as setup_session
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from cryptography import fernet
import ldap3
from ldap3.core.exceptions import LDAPAttributeError, LDAPException

from onelogin.saml2.auth import OneLogin_Saml2_Auth

from app.service.interfaces.i_auth_svc import AuthServiceInterface
from app.utility.base_service import BaseService


def for_all_public_methods(decorator):
    """class decorator -- adds decorator to all public methods"""

    def decorate(cls):
        for attr in cls.__dict__:
            if callable(getattr(cls, attr)) and attr[0] != '_':
                setattr(cls, attr, decorator(getattr(cls, attr)))
        return cls

    return decorate


def check_authorization(func):
    """
    Authorization Decorator
    This requires that the calling class have `self.auth_svc` set to the authentication service.
    """
    async def process(func, *args, **params):
        return await func(*args, **params)

    async def helper(*args, **params):
        if len(args) > 1 and type(args[1]) is web_request.Request:
            await args[0].auth_svc.check_permissions('app', args[1])
        result = await process(func, *args, **params)
        return result
    return helper


class AuthService(AuthServiceInterface, BaseService):

    User = namedtuple('User', ['username', 'password', 'permissions'])

    def __init__(self):
        self.user_map = dict()
        self.log = self.add_service('auth_svc', self)
        self.ldap_config = self.get_config('ldap')
        self._saml_config = self.get_config('saml')
        self.saml_enabled = self.get_config('saml_enabled')

    async def apply(self, app, users):
        if users:
            for group, user in users.items():
                self.log.debug('Created authentication group: %s' % group)
                for username, password in user.items():
                    await self.create_user(username, password, group)
        app.user_map = self.user_map
        fernet_key = fernet.Fernet.generate_key()
        secret_key = base64.urlsafe_b64decode(fernet_key)
        storage = EncryptedCookieStorage(secret_key, cookie_name='API_SESSION')
        setup_session(app, storage)
        policy = SessionIdentityPolicy()
        setup_security(app, policy, DictionaryAuthorizationPolicy(self.user_map))

    async def create_user(self, username, password, group):
        self.user_map[username] = self.User(username, password, (group, 'app'), )

    @staticmethod
    async def logout_user(request):
        await forget(request, web.Response())
        raise web.HTTPFound('/login')

    async def login_user(self, request):
        """
        Log a user in and save the session
        :param request:
        :return: the response/location of where the user is trying to navigate
        """
        self.log.debug('Logging in user')
        data = await request.post()
        username = data.get('username')
        password = data.get('password')
        if self.ldap_config:
            verified = await self._ldap_login(username, password)
        elif self.saml_enabled and not (username or password):
            # If login attempt did not contain username or password, and SAML is enabled, then redirect
            # to identity provider login page.
            await self.saml_redirect(request)
        else:
            verified = await self._check_credentials(request.app.user_map, username, password)

        if verified:
            await self.provide_verified_login_response(request, username)
        self.log.debug('%s failed login attempt: ' % username)
        raise web.HTTPFound('/login')

    async def provide_verified_login_response(self, request, username):
        self.log.debug('%s logging in:' % username)
        response = web.HTTPFound('/')
        await remember(request, response, username)
        raise response

    async def check_permissions(self, group, request):
        try:
            if request.headers.get('KEY') == self.get_config('api_key_red') or \
                    request.headers.get('KEY') == self.get_config('api_key_blue'):
                return True
            await check_permission(request, group)
        except (HTTPUnauthorized, HTTPForbidden):
            if self.saml_enabled:
                await self.saml_redirect(request)
            raise web.HTTPFound('/login')

    async def get_permissions(self, request):
        identity_policy = request.config_dict.get('aiohttp_security_identity_policy')
        identity = await identity_policy.identify(request)
        if identity in self.user_map:
            return [self.Access[p.upper()] for p in self.user_map[identity].permissions]
        elif request.headers.get('KEY') == self.get_config('api_key_red'):
            return self.Access.RED, self.Access.APP
        elif request.headers.get('KEY') == self.get_config('api_key_blue'):
            return self.Access.BLUE, self.Access.APP
        return ()

    async def saml_login(self, request):
        saml_response = await self._prepare_auth_parameter(request)
        saml_auth = OneLogin_Saml2_Auth(saml_response, self._saml_config)
        saml_auth.process_response()
        errors = saml_auth.get_errors()
        if errors:
            self.log.error('Error when processing SAML response: %s' % ', '.join(errors))
        else:
            if saml_auth.is_authenticated():
                username = self._get_saml_login_username(saml_auth)
                self.log.debug('SAML provided username: %s' % username)
                if username:
                    if username in self.user_map:
                        await self.provide_verified_login_response(request, username)
                    else:
                        self.log.warn('Username %s not configured for login' % username)
                else:
                    self.log.error('No NameID or username attribute provided in SAML response.')
            else:
                self.log.warn('Not authenticated.')

    async def saml_redirect(self, request):
        """Will raise web.HTTPFound for identity provider redirect on success."""

        try:
            saml_request = await self._prepare_auth_parameter(request)
            auth = OneLogin_Saml2_Auth(saml_request, self._saml_config)
            redirect = auth.login()
            raise web.HTTPFound(redirect)
        except web.HTTPRedirection as http_redirect:
            raise http_redirect
        except Exception as e:
            self.log.error('Error redirecting to SAML identity provider: %s' % e)

    """ PRIVATE """

    @staticmethod
    def _get_saml_login_username(saml_auth):
        """If the SAML subject NameID is provided, use that as the username. Otherwise, use the 'username'
        attribute if available."""

        name_id = saml_auth.get_nameid()
        if name_id:
            return name_id
        attributes = saml_auth.get_attributes()
        username_attr_list = attributes.get('username', [])
        return username_attr_list[0] if len(username_attr_list) > 0 else None

    @staticmethod
    async def _prepare_auth_parameter(request):
        ret_parameters = {
            'http_host': request.url.host,
            'script_name': request.url.path,
            'server_port': request.url.port,
            'get_data': request.url.query.copy(),
            'post_data': (await request.post()).copy(),
        }
        return ret_parameters

    @staticmethod
    async def _check_credentials(user_map, username, password):
        user = user_map.get(username)
        if not user:
            return False
        return user.password == password

    async def _ldap_login(self, username, password):
        server = ldap3.Server(self.ldap_config.get('server'))
        dn = self.ldap_config.get('dn')
        user_attr = self.ldap_config.get('user_attr') or 'uid'
        user_string = '%s=%s,%s' % (user_attr, username, dn)

        try:
            with ldap3.Connection(server, user=user_string, password=password) as conn:
                if conn.bind():
                    if username not in self.user_map:
                        group = await self._ldap_get_group(conn, dn, username, user_attr)
                        await self.create_user(username, None, group)
                    return True
        except LDAPException:
            self.log.error('Unable to connect to LDAP server')

        return False

    async def _ldap_get_group(self, connection, dn, username, user_attr):
        group_attr = self.ldap_config.get('group_attr') or 'objectClass'
        red_group_name = self.ldap_config.get('red_group') or 'red'

        try:
            connection.search(dn, '(%s=%s)' % (user_attr, username), attributes=[group_attr])
        except LDAPAttributeError:
            self.log.error('Invalid group_attr in config: %s' % group_attr)
            return 'blue'

        groups_result = connection.entries[0][group_attr].value
        if ((isinstance(groups_result, list) and red_group_name in groups_result)
                or red_group_name == groups_result):
            return 'red'
        else:
            return 'blue'


class DictionaryAuthorizationPolicy(AbstractAuthorizationPolicy):

    def __init__(self, user_map):
        super().__init__()
        self.user_map = user_map

    async def authorized_userid(self, identity):
        """Retrieve authorized user id.
        Return the user_id of the user identified by the identity
        or 'None' if no user exists related to the identity.
        """
        if identity in self.user_map:
            return identity

    async def permits(self, identity, permission, context=None):
        """Check user permissions.
        Return True if the identity is allowed the permission in the
        current context, else return False.
        """
        user = self.user_map.get(identity)
        if not user:
            return False
        return permission in user.permissions
