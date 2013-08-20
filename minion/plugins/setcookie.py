# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import logging
import json
import os
import re
import requests

from minion.plugins.base import BlockingPlugin, ExternalProcessPlugin

# SetCookie checker using BlockingPlugin
class SetCookiePlugin(BlockingPlugin):
    PLUGIN_NAME = "SetCookie"
    PLUGIN_VERSION = "0.1"

    FURTHER_INFO = [ {"URL": "http://msdn.microsoft.com/en-us/library/windows/desktop/aa384321%28v=vs.85%29.aspx",
                      "Title": "MSDN - HTTP Cookies"} ]
    def do_run(self):
        # We only plan on checking whether HttpOnly and 
        # secure flags are enabled. Valdating other
        # parts of the Set-Cookie header will bloat
        # up this example.

        r = requests.get(self.configuration['target'])
        if 'set-cookie' not in r.headers:
            return self.report_issues([
                {'Summary': "Site has no Set-Cookie header",
                 'Description': "The Set-Cookie header is sent by the server in response to an HTTP request, which is \
used to create a cookie on the user's system.",
                 'Severity': "Info",
                 "URLs": [ {"URL": None, "Extra": None} ],
                 "FurtherInfo": self.FURTHER_INFO}])
        else:
            set_cookies_val = re.split('\s*;\s*', r.headers['set-cookie'])
            found_risk = False
            if 'secure' not in set_cookies_val:
                found_risk = True
                new_cookie = 'Set-Cookie: ' + r.headers['set-cookie'] + '; secure;'
                self.report_issues([
                    {'Summary': 'secure flag is not set in the Set-Cookie header',
                     'Description': 'If the cookies containing user sensitive information, consider adding the secure flag \
to the Set-Cookie header. The final cookie setting may look like this: %s' % new_cookie,
                     'Severity': 'High',
                     "FurtherInfo": [ {"URL": "http://msdn.microsoft.com/en-us/library/windows/desktop/aa384321%28v=vs.85%29.aspx",
                            "Title": "MSDN - HTTP Cookies"} ],
                     'URLs': [ {'URL': None, 'Extra': None} ],
                     "FurtherInfo": self.FURTHER_INFO}])
            if 'HttpOnly' not in set_cookies_val:
                found_risk = True
                new_cookie = 'Set-Cookie: ' + r.headers['set-cookie'] + '; HttpOnly;'
                self.report_issues([
                    {'Summary': 'HttpOnly flag is not set in the Set-Cookie header',
                     'Description': 'If the HttpOnly flag (optional) is included in the HTTP response header, the cookie \
cannot be accessed through client side script (again if the browser supports this flag). As a result, even if a cross-site \
scripting (XSS) flaw exists, and a user accidentally accesses a link that exploits this flaw, the browser (primarily \
Internet Explorer) will not reveal the cookie to a third party. The final cookie setting may look like this: %s' % new_cookie,
                     'Severity': 'High',
                     'URLs': [ {'URL': None, 'Extra': None} ],
                     'FurtherInfo': self.FURTHER_INFO}])

            # if remains as False, we know both flags are set
            if not found_risk:
                self.report_issues([
                    {'Summary': 'Site has both HttpOnly and secure flags set properly',
                     'Description': 'Cookies can only be transferred over a secured channel and cookies is not accessible \
through client side script.',
                     'Severity': 'Info',
                     'URLs': [ {'URL': None, 'Extra': None} ],
                     'FurtherInfo': self.FURTHER_INFO}])
            return


# Set-Cookie checker by running setcookie scanner written in Go
class SetCookieScannerPlugin(ExternalProcessPlugin):
    PLUGIN_NAME = "SetCookieScanner"
    PLUGIN_VERSION = "0.1"

    def do_start(self):
        scanner_path = self.locate_program("setcookie_scanner")
        if not scanner_path:
            raise Exception("Cannot find setcookie_scanner program.")

        self.stdout = ""
        self.stderr = ""

        # spawn by calling the executable and a list of args
        self.spawn(scanner_path, [self.configuration['target']])
       
    def do_process_stdout(self, data):
        self.stdout += data
    
    def do_process_stderr(self, data):
        self.stderr += data

    def do_process_ended(self, process_status):
        if self.stopping and process_statsu == 9:
            self.report_finish("STOPPED")
        elif process_status == 0:
            # try to convert the JSON outputs in stdout
            stdouts = self.stdout.split('\n')
            minion_issues = []
            for stdout in stdouts:
                try:
                    minion_issues.append(json.loads(stdout))
                except ValueError:
                    logging.info(stdout)
                    pass

            self.report_issues(minion_issues)
            self.report_finish()
        else:
            self.report_finish("FAILED")
