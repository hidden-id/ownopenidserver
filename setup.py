#!/usr/bin/env python

from distutils.core import setup

setup(
        name='openidserver',
        author='Vladimir S Eremin (aka yottatsa)',
        author_email='me@yottatsa.name',
        url='http://ownopenidserver.com/',
        version='1.0',
        packages=['openidserver'],
        install_requires = ['python-openid', 'web.py', 'flup', 'pystache'],
        package_data = {
            'openidserver': [
                        'templates',
                        'static'
                    ],
            },
)
