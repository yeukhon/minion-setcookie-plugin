# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from setuptools import setup

install_requires = [
    'minion-backend',
    'requests'
]

setup(name="minion-setcookie-plugin",
      version="0.1",
      description="A Minion plugin that detects whether Set-Cookie has HttpOnly and secure flags set properly.",
      url="https://github.com/yeukhon/minion-setcookie-plugin/",
      author="Yeuk Hon Wong",
      author_email="yeukhon@acm.org",
      packages=['minion', 'minion.plugins'],
      namespace_packages=['minion', 'minion.plugins'],
      include_package_data=True,
      install_requires = install_requires)
