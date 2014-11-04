#!/usr/bin/env python

import os, os.path
import urlparse
import urllib
import sys
import hashlib, random

import pystache, json

import web, web.http, web.form, web.session

import openid.server.server, openid.store.filestore, openid.fetchers
try:
    from openid.extensions import sreg
except ImportError:
    from openid import sreg
    
def login_required(f):
    def decorated(*args,**kwargs):
        if not session.logged_in:
            return WebOpenIDLoginRequired(args[0].query)
        return f(*args,**kwargs)
    return decorated

def csrf_token():
    if not session.has_key('csrf_token'):
        from uuid import uuid4
        session.csrf_token=uuid4().hex
    return session.csrf_token

def csrf_protected(f):
    def decorated(*args,**kwargs):
        try:
            meth = args[0].method
        except:
            meth = None
        if meth == 'POST':
            inp = web.input()
            if not (inp.has_key('csrf_token') and inp.csrf_token==session.pop('csrf_token',None)):
                raise web.HTTPError(
                    "400 Bad request",
                    {'content-type':'text/html'},
                    'Cross-site request forgery (CSRF) attempt (or stale browser form).'
                    '<a href="">Back to the form</a>.')
        return f(*args,**kwargs)
    return decorated

def publichomedomain():
    """
    Returns *.onion (not localhost:*) when request is via
    a hidden tor service (unlike web.ctx.homedomain).
    """
    return '{0}://{1}'.format(web.ctx.protocol,web.ctx.env['HTTP_HOST'])

class TrustRootStore(object):
    """
    Store and lookup over trust root list
    """

    def __init__(self, directory):
        self.directory = directory
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)


    def _get_filename(self, url):
        """
        Encode url to filename
        TODO: doctest
        """

        url = urlparse.urlparse(url)
        filename = urllib.quote('__'.join(tuple(url)).replace('/', '_'))

        return os.path.join(self.directory, filename)


    def items(self):
        return [(item, os.readlink(os.path.join(self.directory, item)))
                for item in os.listdir(self.directory)
                if os.path.islink(os.path.join(self.directory, item))]


    def add(self, url):
        return os.symlink(url, self._get_filename(url))


    def check(self, url):
        return os.path.lexists(self._get_filename(url))


    def delete(self, url):
        return os.unlink(self._get_filename(url))


class OpenIDResponse(object):
    """
    Handle requests to OpenID, including trust root lookups
    """


    class NoneRequest(Exception):
        """
        Raise if request is empty
        """
        pass


    class DecisionNeed(Exception):
        """
        Raise if user decision of approve or decline autorization need
        """
        pass


    class LogInNeed(Exception):
        """
        Raise if need user to be logged in
        """
        pass


    def _encode_response(self, response):
        self.response = response
        self.webresponse = self.openid.encodeResponse(self.response)
        return self.webresponse


    def __init__(self, server, openid, query):
        """
        Decode request
        """

        self.server = server
        self.openid = openid
        self.query = query

        # parse openid request
        self.request = self.openid.decodeRequest(query)


    def process(self, logged_in=False):
        """
        Main checks routine
        """

        # no request
        if self.request is None:
            raise OpenIDResponse.NoneRequest

        if self.request.mode in ["checkid_immediate", "checkid_setup"]:
            # check request

            if not logged_in:
                # this stage required restricted access to endpoint
                raise OpenIDResponse.LogInNeed

            if self.server.trust_root_store.check(self.request.trust_root):
                # approve if request from trustroot
                return self.approve()

            elif self.request.immediate:
                # decline if immediate and not in trustroot
                return self.decline()

            # last hope route to user decision
            raise OpenIDResponse.DecisionNeed


        # return openid.server.server.WebResponse
        return self._encode_response(self.openid.handleRequest(self.request))


    def approve(self, identity=None):
        """
        Approve request

        """

        if identity is None:
            identity = self.request.identity

        response = self.request.answer(
                allow=True,
                identity=identity
            )

        return self._encode_response(response)


    def always(self, identity=None):
        """
        Approve request and to append to trust root store
        """
        self.server.trust_root_store.add(self.request.trust_root)
        return self.approve(identity)


    def decline(self):
        """
        Decline request

        """
        return self._encode_response(self.request.answer(allow=False))


class OpenIDServer(object):
    """
    Manage OpenID server and trust root store, emit response
    """

    def __init__(self, openid_store, trust_root_store):
        self.openid_store = openid_store
        self.trust_root_store = trust_root_store


    def request(self, endpoint, query):
        openid_server = openid.server.server.Server(self.openid_store, endpoint)
        return OpenIDResponse(self, openid_server, query)


class PasswordManager(web.form.Validator):
    """
    Manage access password
    """

    _hashfunc = hashlib.sha512

    class NoPassword(Exception):
        pass

    def __init__(self, directory):
        self.directory = directory
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)

        self.msg = u'Invalid password'


    def _get_filename(self):
        return os.path.join(self.directory, 'password')


    def _generate_hash(self, salt, password):
        """
        build hash as _hashfunc of concat of salt and password
        """
        hash = self._hashfunc()
        hash.update(salt.encode('utf8'))
        hash.update(password.encode('utf8'))
        return hash.hexdigest()


    def valid(self, password):
        """
        Check password. Return False if passwords don't match, else return True if
        passwords match or unavailable
        """
        try:
            file = open(self._get_filename(), 'rb+')

            # read salt and hash splitted by '$' from password file
            salt, hash = file.read().strip().split('$', 1)

            file.close()

            # build hash and compare with stored
            if not self._generate_hash(salt, password) == hash:
                return False

        except:
            raise PasswordManager.NoPassword

        return True


    def set(self, password):
        """
        Set password
        """
        try:
            file = open(self._get_filename(), 'wb+')
            salt = str(random.randint(1, sys.maxint))

            file.write('$'.join([salt, self._generate_hash(salt, password)]))

            file.close()
            return True
        except:
            raise


class Session(web.session.Session):

    def login(self):
        session['logged_in'] = True

    def logout(self):
        session['logged_in'] = False

    @property
    def logged_in(self):
        return session.get('logged_in', False)


def render_openid_to_response(response):
    """
    Return WebResponse as web.py response
    """
    if response.code in [200]:
        for name, value in response.headers.items():
            web.header(name, value)
        return response.body
    elif response.code in [302] and response.headers.has_key('location'):
        return web.found(response.headers['location'])
    else:
        return web.HTTPError(str(response.code) + ' ', response.headers)


class WebHandler(object):


    def __init__(self):
        self.query = web.input()
        self.method = None


    def GET(self, *args, **kwargs):
        self.method = 'GET'
        return self.request(*args, **kwargs)


    def POST(self, *args, **kwargs):
        self.method = 'POST'
        return self.request(*args, **kwargs)


    def request(self):
        raise NotImplemented


class WebOpenIDIndex(WebHandler):


    def request(self):
        web.header('Content-type', 'text/html')
        return stache.render_name('home',
                title='Profile',
                is_home=True,
                profile=profile,
                csrf_token=csrf_token(),
                logged_in=session.logged_in,
                hiddenid=publichomedomain() + web.url('/'),
                login_url=publichomedomain() + web.url('/account/login'),
                logout_url=publichomedomain() + web.url('/account/logout'),
                change_password_url=publichomedomain() + web.url('/account/change_password'),
                check_trusted_url=publichomedomain() + web.url('/account/trusted'),
                no_password=session.get('no_password', False),
                endpoint=publichomedomain() + web.url('/endpoint'),
                yadis=publichomedomain() + web.url('/yadis.xrds'),
            )


def WebOpenIDLoginRequired(query):
    query['return_to'] = publichomedomain() + web.url(web.ctx.path)
    return web.found(publichomedomain() + web.url('/account/login', **query))


def WebOpenIDLoginForm(validator):
    return web.form.Form(
            web.form.Password("password",
                validator,
                description="Password: ",
            ),
        )


class WebOpenIDLogin(WebHandler):

    @csrf_protected
    def request(self):
        return_to = self.query.get('return_to', publichomedomain() + web.url('/'))
        if session.logged_in:
            return web.found(return_to)

        data = [
            {'key':pair[0],'value':pair[1]}
            for pair in self.query.items()
            if pair[0]!='password'
        ]
        return_to_query = dict([
            (item['key'],item['value'])
            for item in data
            if not item['key'] in ['csrf_token','return_to']
        ])
        form = WebOpenIDLoginForm(password_manager)()

        session['no_password'] = False

        if self.method == 'POST':
            try:
                if form.validates(self.query):
                    session.login()
                    data.append(('logged_in', True))
                    return web.found(return_to + '?' + web.http.urlencode(return_to_query))

            except PasswordManager.NoPassword:
                session['no_password'] = True
                session.login()
                data.append(('logged_in', True))
                return web.found(return_to + '?' + web.http.urlencode(return_to_query))

        web.header('Content-type', 'text/html')
        return stache.render_name('login',
                title='Login',
                is_login=True,
                profile=profile,
                csrf_token=csrf_token(),
                logged_in=session.logged_in,
                hiddenid=publichomedomain() + web.url('/'),
                login_url=publichomedomain() + web.url('/account/login')+'?'+web.http.urlencode(
                    {'return_to':return_to}),
                logout_url=publichomedomain() + web.url('/account/logout'),
                change_password_url=publichomedomain() + web.url('/account/change_password'),
                no_password=session.get('no_password', False),
                check_trusted_url=publichomedomain() + web.url('/account/trusted'),
                form_render=form.render().replace('<table>','').replace('</table>',''),
                query=data
            )


class WebOpenIDLogout(WebHandler):

    @csrf_protected
    def request(self):
        if self.method=='POST':
            session.logout()
            return web.found(publichomedomain() + web.url('/'))
        return web.found(publichomedomain() + web.url('/'))


WebOpenIDChangePasswordForm = web.form.Form(
            web.form.Password("password",
                web.form.notnull,
                description="Password: ",
            ),
            web.form.Password("confirm",
                web.form.notnull,
                description="Retype: ",
            ),
            validators=[
                    web.form.Validator('Passwords did not match',
                        lambda source: source['password'] == source['confirm']),
                ],
        )


class WebOpenIDChangePassword(WebHandler):


    @login_required
    @csrf_protected
    def request(self):

        form = WebOpenIDChangePasswordForm()

        if self.method == 'POST':
            if form.validates(self.query):
                password_manager.set(self.query['password'])

                session['no_password'] = False

                return web.found(publichomedomain() + web.url('/'))

        web.header('Content-type', 'text/html')
        return stache.render_name('password',
                title='Change password',
                is_password=True,
                profile=profile,
                csrf_token=csrf_token(),
                logged_in=session.logged_in,
                hiddenid=publichomedomain() + web.url('/'),
                login_url=publichomedomain() + web.url('/account/login'),
                logout_url=publichomedomain() + web.url('/account/logout'),
                change_password_url=publichomedomain() + web.url('/account/change_password'),
                check_trusted_url=publichomedomain() + web.url('/account/trusted'),
                no_password=session.get('no_password', False),
                form_render=form.render().replace('<table>','').replace('</table>',''),
            )


class WebOpenIDTrusted(WebHandler):

    @login_required
    def request(self):
        items = [
            {'id':item[0],'name':item[1]}
            for item in trust_root_store.items()
        ]

        removed = session.get('trusted_removed_successful', False)
        session['trusted_removed_successful'] = False

        web.header('Content-type', 'text/html')
        return stache.render_name('trusted',
                title='Trusted sites',
                is_trusted=True,
                profile=profile,
                csrf_token=csrf_token(),
                logged_in=session.logged_in,
                hiddenid=publichomedomain() + web.url('/'),
                login_url=publichomedomain() + web.url('/account/login'),
                logout_url=publichomedomain() + web.url('/account/logout'),
                change_password_url=publichomedomain() + web.url('/account/change_password'),
                check_trusted_url=publichomedomain() + web.url('/account/trusted'),
                no_password=session.get('no_password', False),
                trusted=items,
                removed=removed,
            )


class WebOpenIDTrustedDelete(WebHandler):


    @login_required
    @csrf_protected
    def request(self, trusted_id):

        try:
            trust_root = dict(trust_root_store.items())[trusted_id]
        except:
            return web.notfound()

        if self.method == 'POST':
                trust_root_store.delete(trust_root)

                session['trusted_removed_successful']  = True

                return web.found(publichomedomain() + web.url('/account/trusted'))

        web.header('Content-type', 'text/html')
        return stache.render_name('trusted_confirm',
                title='Confirm trust removal',
                profile=profile,
                csrf_token=csrf_token(),
                logged_in=session.logged_in,
                hiddenid=publichomedomain() + web.url('/'),
                login_url=publichomedomain() + web.url('/account/login'),
                logout_url=publichomedomain() + web.url('/account/logout'),
                change_password_url=publichomedomain() + web.url('/account/change_password'),
                check_trusted_url=publichomedomain() + web.url('/account/trusted'),
                no_password=session.get('no_password', False),
                trust_root=trust_root,
            )


class WebOpenIDYadis(WebHandler):


    def request(self):
        import openid.consumer
        web.header('Content-type', 'application/xrds+xml')
        return """<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
    <XRD>
        <Service priority="0">
            <Type>%s</Type>
            <Type>%s</Type>
            <URI>%s</URI>
            <LocalID>%s</LocalID>
        </Service>
    </XRD>
</xrds:XRDS>\n""" %\
            (
                openid.consumer.discover.OPENID_2_0_TYPE,
                openid.consumer.discover.OPENID_1_0_TYPE,
                publichomedomain() + web.url('/endpoint'),
                publichomedomain(),
            )


class WebOpenIDEndpoint(WebHandler):


    def request(self):
        request = server.request(publichomedomain() + web.url('/endpoint'), self.query)
        try:
            response = request.process(session.logged_in)

        except OpenIDResponse.NoneRequest:
            return web.badrequest()

        except OpenIDResponse.LogInNeed:
            # redirect request to login form
            return WebOpenIDLoginRequired(self.query)

        except OpenIDResponse.DecisionNeed:
            # redirect request to decision page in restricted area
            return web.found(publichomedomain() + web.url('/account/decision', **self.query))

        if self.query.get('logged_in', False):
            session.logout()


        return render_openid_to_response(response)


WebOpenIDLogoutForm = web.form.Form(
            web.form.Checkbox("logout", description="Log out after"),
        )


class WebOpenIDDecision(WebHandler):


    @login_required
    @csrf_protected
    def request(self):

        request = server.request(publichomedomain() + web.url('/endpoint'), self.query)

        try:
            response = request.process(logged_in=True)

        except OpenIDResponse.NoneRequest:
            return web.badrequest()

        except OpenIDResponse.DecisionNeed:

            if self.method == 'POST':
                if self.query.get('logout', False):
                    session.logout()

                if self.query.has_key('approve'):
                    response = request.approve()
                elif self.query.has_key('always'):
                    response = request.always()
                else:
                    response = request.decline()

            else:
                data = [
                    {'key':pair[0],'value':pair[1]}
                    for pair in self.query.items()
                    if pair[0] not in [
                        'approve', 'always', 'logged_in', 'logout', 'csrf_token'
                    ]
                ]

                sreg_request = sreg.SRegRequest.fromOpenIDRequest(request.request)

                logout_form = WebOpenIDLogoutForm()
                logout_form.fill({'logout': self.query.get('logged_in', False)})

                web.header('Content-type', 'text/html')
                return stache.render_name('verify',
                        title='Verification request',
                        profile=profile,
                        csrf_token=csrf_token(),
                        logged_in=session.logged_in,
                        hiddenid=publichomedomain() + web.url('/'),
                        login_url=publichomedomain() + web.url('/account/login'),
                        logout_url=publichomedomain() + web.url('/account/logout'),
                        change_password_url=publichomedomain() + web.url('/account/change_password'),
                        check_trusted_url=publichomedomain() + web.url('/account/trusted'),
                        no_password=session.get('no_password', False),
                        decision_url=publichomedomain() + web.url('/account/decision'),
                        identity=request.request.identity,
                        trust_root=request.request.trust_root,
                        logout_form=logout_form,
                        query=data,
                    )

        return render_openid_to_response(response)


def init(
            root_store_path,
            trust_root_store_path,
            session_store_path,
            password_store_path,
            templates_path,
            debug=False
        ):

    context = globals()

    app = web.application(
            (
                '', 'WebOpenIDIndex',
                '/', 'WebOpenIDIndex',
                '/account', 'WebOpenIDIndex',
                '/account/login', 'WebOpenIDLogin',
                '/account/logout', 'WebOpenIDLogout',
                '/account/change_password', 'WebOpenIDChangePassword',
                '/account/trusted', 'WebOpenIDTrusted',
                '/account/trusted/(?P<trusted_id>[^/]+)/delete', 'WebOpenIDTrustedDelete',
                '/yadis.xrds', 'WebOpenIDYadis',
                '/endpoint', 'WebOpenIDEndpoint',
                '/account/decision', 'WebOpenIDDecision',
            ),
            context,
        )


    openid_store = openid.store.filestore.FileOpenIDStore(root_store_path)
    trust_root_store = TrustRootStore(trust_root_store_path)
    server = OpenIDServer(openid_store, trust_root_store)
    context['trust_root_store'] = trust_root_store
    context['server'] = server

    sessions_store = web.session.DiskStore(session_store_path)
    session = Session(app, sessions_store)
    context['session'] = session

    password_manager = PasswordManager(password_store_path)
    context['password_manager'] = password_manager

    stache = pystache.Renderer(search_dirs=templates_path,
        file_encoding='utf-8', string_encoding='utf-8', file_extension='html')
    context['stache'] = stache

    profile_filename = os.path.join(root_store_path,'profile.json')
    if os.path.exists(profile_filename):
        profile = json.load(file(profile_filename))
    else:
        profile = {
            "nickname": "A. Nonymous",
            "description": "Someone who didn't edit sstore/profile.json [yet?] ;)",
            "homepage":"",
            "avatar":"/static/img/default-avatar.png"
        }
        json.dump(profile,file(profile_filename,"w"),indent=4)
    context['profile'] = profile

    web.config.debug = debug

    return app


if __name__ == '__main__':
    ROOT_STORE = 'sstore'
    TEMPLATES = 'templates'

    TRUST_ROOT_STORE = os.path.join(ROOT_STORE, 'trust_root')
    SESSION_STORE = os.path.join(ROOT_STORE, 'sessions')
    PASSWORD_STORE = ROOT_STORE
    init(ROOT_STORE, TRUST_ROOT_STORE, SESSION_STORE, PASSWORD_STORE, TEMPLATES, True).run()
