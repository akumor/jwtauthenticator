from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
from tornado import gen, web
from traitlets import Unicode, Bool
from jose import jwt, JWTError
import requests

class JSONWebTokenLoginHandler(BaseHandler):

    def get(self):
        self.log.info("Called JSONWebTokenLoginHandler.get")
        header_name = self.authenticator.header_name
        param_name = self.authenticator.param_name
        header_is_authorization = self.authenticator.header_is_authorization

        auth_header_content = self.request.headers.get(header_name, "")
        auth_cookie_content = self.get_cookie("XSRF-TOKEN", "")
        signing_certificate = self.authenticator.signing_certificate
        jwks_url = self.authenticator.jwks_url
        secret = self.authenticator.secret
        username_claim_field = self.authenticator.username_claim_field
        audience = self.authenticator.expected_audience
        tokenParam = self.get_argument(param_name, default=False)

        if auth_header_content and tokenParam:
            self.log.info("JSONWebTokenLoginHandler | 400 auth_header_content and tokenParam")
            raise web.HTTPError(400)
        elif auth_header_content:
            self.log.info("JSONWebTokenLoginHandler | token auth_header_content")
            if header_is_authorization:
                self.log.info("JSONWebTokenLoginHandler | token auth_header_content header_is_authorization")
                # we should not see "token" as first word in the AUTHORIZATION header, if we do it could mean someone coming in with a stale API token
                if auth_header_content.split()[0] != "bearer":
                    self.log.info("JSONWebTokenLoginHandler | token auth_header_content 403 not bearer")
                    raise web.HTTPError(403)
                token = auth_header_content.split()[1]
            else:
                self.log.info("JSONWebTokenLoginHandler | token auth_header_content else")
                token = auth_header_content
        elif auth_cookie_content:
            self.log.info("JSONWebTokenLoginHandler | token auth_cookie_content")
            token = auth_cookie_content
        elif tokenParam:
            self.log.info("JSONWebTokenLoginHandler | token tokenParam")
            token = tokenParam
        else:
            self.log.info("JSONWebTokenLoginHandler | 401 err no auth")
            raise web.HTTPError(401)

        claims = ""
        if secret:
            self.log.info("JSONWebTokenLoginHandler | secret claims")
            claims = self.verify_jwt_using_secret(token, secret, audience)
        elif signing_certificate:
            self.log.info("JSONWebTokenLoginHandler | signing_certificate claims")
            claims = self.verify_jwt_with_claims(token, signing_certificate, audience)
        elif jwks_url:
            self.log.info("JSONWebTokenLoginHandler | jwks_url claims")
            claims = self.verify_jwt_with_jwks(token, jwks_url, audience)
        else:
            self.log.info("JSONWebTokenLoginHandler | 401 err no claims")
            raise web.HTTPError(401)

        self.log.info("JSONWebTokenLoginHandler | set login cookie")
        username = self.retrieve_username(claims, username_claim_field)
        user = self.user_from_username(username)
        self.set_login_cookie(user)

        self.log.info("JSONWebTokenLoginHandler | redirecting to /home")
        _url = url_path_join(self.hub.server.base_url, 'home')
        next_url = self.get_argument('next', default=False)
        if next_url:
             _url = next_url

        self.redirect(_url)

    @staticmethod
    def verify_jwt_with_claims(token, signing_certificate, audience):
        # If no audience is supplied then assume we're not verifying the audience field.
        if audience == "":
            opts = {"verify_aud": False}
        else:
            opts = {}
        with open(signing_certificate, 'r') as rsa_public_key_file:
            return jwt.decode(token, rsa_public_key_file.read(), audience=audience, options=opts)

    @staticmethod
    def verify_jwt_using_secret(json_web_token, secret, audience):
        # If no audience is supplied then assume we're not verifying the audience field.
        if audience == "":
            opts = {"verify_aud": False}
        else:
            opts = {}
        
        return jwt.decode(json_web_token, secret, algorithms=list(jwt.ALGORITHMS.SUPPORTED), audience=audience, options=opts)

    @staticmethod
    def verify_jwt_with_jwks(token, jwks_url, audience):
        # If no audience is supplied then assume we're not verifying the audience field.
        opts = {"verify_aud": False} if audience == "" else {}
        # Retrieve the JWKS from the URL
        jwks = JSONWebTokenLoginHandler.retrieve_jwks(jwks_url)
        # Decode the JWT header to get the kid
        header = jwt.get_unverified_header(token)
        kid = header['kid']
        # Find the key in the JWK set that matches the kid
        key = next((key for key in jwks['keys'] if key['kid'] == kid), None)
        if not key:
            raise Exception("Public key not found in JWK set")
        # Convert the key to the format required by python-jose
        public_key = {
            'kty': key['kty'],
            'kid': key['kid'],
            'use': key['use'],
            'n': key['n'],
            'e': key['e']
        }
        # Verify the JWT
        try:
            return jwt.decode(token, public_key, algorithms=list(jwt.ALGORITHMS.SUPPORTED), audience=audience, options=opts)
        except JWTError as e:
            self.log.error("Invalid token: "+str(e))
            return {}

    @staticmethod
    def retrieve_username(claims, username_claim_field):
        # retrieve the username from the claims
        username = claims[username_claim_field]
        if "@" in username:
            # process username as if email, pull out string before '@' symbol
            return username.split("@")[0]

        else:
            # assume not username and return the user
            return username

    @staticmethod
    def retrieve_jwks(jwk_url: str):
        response = requests.get(jwk_url)
        return response.json()


class JSONWebTokenAuthenticator(Authenticator):
    """
    Accept the authenticated JSON Web Token from header.
    """
    signing_certificate = Unicode(
        config=True,
        help="""
        The public certificate of the private key used to sign the incoming JSON Web Tokens.

        Should be a path to an X509 PEM format certificate filesystem.
        """
    )

    jwks_url = Unicode(
        config=True,
        help="""
        The URL of the JWKS endpoint that contains the public keys used to verify the
        incoming JSON Web Tokens.
        """
    )

    username_claim_field = Unicode(
        default_value='upn',
        config=True,
        help="""
        The field in the claims that contains the user name. It can be either a straight username,
        of an email/userPrincipalName.
        """
    )

    expected_audience = Unicode(
        default_value='',
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token."""
    )

    header_name = Unicode(
        default_value='Authorization',
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token.""")
        
    header_is_authorization = Bool(
        default_value=True,
        config=True,
        help="""Treat the inspected header as an Authorization header.""")

    param_name = Unicode(
        config=True,
        default_value='access_token',
        help="""The name of the query parameter used to specify the JWT token""")

    secret = Unicode(
        config=True,
        help="""Shared secret key for siging JWT token.  If defined, it overrides any setting for signing_certificate""")

    def get_handlers(self, app):
        return [
            (r'/login', JSONWebTokenLoginHandler),
        ]

    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()


class JSONWebTokenLocalAuthenticator(JSONWebTokenAuthenticator, LocalAuthenticator):
    """
    A version of JSONWebTokenAuthenticator that mixes in local system user creation
    """
    pass
