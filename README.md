minion-setcookie-plugin
=======================

A Minion plugin that detects whether Set-Cookie has HttpOnly and secure flags set properly.


Usage:
------

    sudo apt-get install golang
    git clone https://github.com/yeukhon/minion-setcookie-plugin
    cd minion-setcookie-plugin
    ./setup.sh develop

This plugin is served as an example for an upcoming Minion blog post. There are two plugin
classes:

* ``SetCookiePlugin``

* ``SetCookieScannerPlugin``

The first one subclasses ``BlockingPlugin`` and uses the requests library to make HTTP call. The
second one subclasses ``ExternalProcessPlugin`` and depends on a small program written in Go. 
This program mirrors everything ``SetCookiePlugin`` does, except the code is in written in Go.


The ``setup.sh`` file will recompile the go program for you and make a symbolic link to ``/usr/bin/setcookie_scanner``.


