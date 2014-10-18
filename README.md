ownopenidserver
===============

*ownopenidserver* is a small and very own OpenID server for your site.

Application can work as standalone web server (you can use it for testing and
development puproses) as well as CGI or FastCGI application. While running,
application provides two basic services.

- OpenID provider for those consumers (relying parties) which you want to be
  authenticated in.
- Web interfaces for management your personal account.

*ownopenidserver* relies on and depends on these external modules:

- [python-openid][] for sure
- [web.py][] provides lihgtweight HTTP and CGI inteface and web framework
- [flup][] provides FastCGI interface for web.py
- [Pystache][] is used for mustache html template rendering

[python-openid]: http://pypi.python.org/pypi/python-openid/
[web.py]: http://webpy.org/
[flup]: http://www.saddi.com/software/flup/
[Pystache]: https://pypi.python.org/pypi/pystache

Initial setup
--------------

Before starting using this server as your main provider, probably you'd like to
play with it a little.

So, make sure that all mentioned dependenices are installed and then type

    cd openidserver
    python ./openidserver.py

Thanks to web2py leverage, the server will be launched with default settings on
a port 8080 listening all your interfaces.

Follow http://localhost:8080/ URL. After the first setup there is only one "log
in" link leading to http://localhost:8080/account/login . You can login with an
empty password and after that a nice looking page suggests that you
eliminated such a large security breach by providing secure password.

Congratulations, your own openidserver initial configuration completed!


Configuration and settings
---------------------------

By default, once started the server uses directory `sstore` to save your
account's password hash, list of trusted OpenID consumers, associations (shared
secrets between your provider and OpenID relying parties), etc. If you want to
reset your settings, just type from the directory where you have launched your
app:

    rm -rf sstore/*


You can override some application settings to make sure it works smoothly in
your environment. Open `openidserver/openidserver.py` file and scoll down to
the bottom. There is a number of settings there:

- `ROOT_STORE`: directory name with all your settings. Path is relative to
  application's current working directory and points to `sstore` directory by
  default
- `TEMPLATES` is the directory where mustache HTML templates reside
  ('templates' by default)
- `TRUST_ROOT_STORE`, `SESSION_STORE` and `PASSWORD_STORE` are three variables
  which points to different subdirectories in `ROOT_STORE`.  Providing that
  `ROOT_STORE` is defined, you can just left them untouched, unless you have a
  really good reason for doing so.

Next, if you wish to redefine those variables, the right way is to create a
simple launching script which can looks like presented below:

    #!/usr/bin/env python
    from openidserver import openidserver
    ROOT_STORE = 'your/path/to/store'
    TEMPLATES = 'your/path/to/templates'

    TRUST_ROOT_STORE = os.path.join(ROOT_STORE, 'trust_root')
    SESSION_STORE = os.path.join(ROOT_STORE, 'sessions')
    PASSWORD_STORE = ROOT_STORE
    openidserver.init(ROOT_STORE, TRUST_ROOT_STORE, SESSION_STORE, PASSWORD_STORE, TEMPLATES, True).run()

Don't forget to install the application first, so that Python interpreter could
find the openidserver package.

Because of web.py magic, this script can be used as standalone web-server, CGI
or FastCGI application.

What to include on your website page
------------------------------------

Suppose you're the owner of domain example.com and you want to authenticate
yourself in this role.  Assume also, that you have successfully launched
*ownopenidserver* at http://id.example.com (by the way, there is nothing wrong
to place your provider not on a subdomain, but on another address in the same
domain, like "http://example.com/openid").

To achieve your goal, you should edit your website page accessible at
http://example.com/ URL and include in its `<head>` just one tag:

    <link rel="openid.server" href="http://id.example.com/endpoint">

You can also add to your page extra personal data in hCard format. Your
*ownopenidserver* visits your page every time a consumer want to get more info
about you identity.


Project homepage
-----------------

Visit http://ownopenidserver.com for more details.

Bugs and suggestions
--------------------

Please report any bugs you have found to Vladimir S Eremin (aka yottatsa)
<me@yottatsa.name>. Suggestions are also appreciated.
