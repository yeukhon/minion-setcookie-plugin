// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import ( 
    "fmt"
    "encoding/json"
    "net/http"
    "os"
    "regexp"
)


type FurtherInfoFieldType struct {
    URL string `json:"URL"`
    Title string `json:"Title"`
}

type URLsFieldType struct {
    URL string `json:"URL"`
    Extra string `json:"Extra"`
}

type Issue struct {
   Summary string `json:"Summary"`
   Description string `json:"Description"`
   Severity string `json:"Severity"`
   URLs []URLsFieldType `json:"URLs"`
   FurtherInfo []FurtherInfoFieldType `json:"FurtherInfo"`
}


// constants
var FURTHER_INFO = FurtherInfoFieldType{
    URL: "http://msdn.microsoft.com/en-us/library/windows/desktop/aa384321%28v=vs.85%29.aspx",
    Title: "MSDN - HTTP Cookies"}

var URLs = URLsFieldType{
    URL: "",
    Extra: ""}

func reportNoSetCookie() {
    issue := &Issue{
        Summary: "Site has no Set-Cookie header", 
        Description: "The Set-Cookie header is sent by the server in response to an HTTP request, which is used to create a cookie on the user's system.",
        Severity: "Info", 
        URLs: []URLsFieldType{URLs},
        FurtherInfo: []FurtherInfoFieldType{FURTHER_INFO},
    }
    reportIssue(issue)
}

func reportNoSecureFlag(cookie string) {
    description := fmt.Sprintf("If the cookies containing user sensitive information, consider adding the secure flag to the Set-Cookie header. The final cookie setting may look like this: %s", "Set-Cookie: " + cookie + "; secure")

    issue := &Issue{
        Summary: "secure flag is not set in the Set-Cookie header",
        Description: description,
        Severity: "High", 
        URLs: []URLsFieldType{URLs},
        FurtherInfo: []FurtherInfoFieldType{FURTHER_INFO},
    }
    reportIssue(issue)
}

func reportNoHttpOnlyFlag(cookie string) {
    description := fmt.Sprintf("If the HttpOnly flag (optional) is included in the HTTP response header, the cookie cannot be accessed through client side script (again if the browser supports this flag). As a result, even if a cross-site scripting (XSS) flaw exists, and a user accidentally accesses a link that exploits this flaw, the browser (primarily Internet Explorer) will not reveal the cookie to a third party. The final cookie setting may look like this: %s", "Set-Cookie: " + cookie + "; HttpOnly")

    issue := &Issue{
        Summary: "HttpOnly flag is not set in the Set-Cookie header", 
        Description: description,
        Severity: "High", 
        URLs: []URLsFieldType{URLs},
        FurtherInfo: []FurtherInfoFieldType{FURTHER_INFO},
    }
    reportIssue(issue)
}

func reportBothFlagsFound()  {
    issue := &Issue{
        Summary: "Site has both HttpOnly and secure flags set properly",
        Description: "Cookies can only be transferred over a secured channel and cookies is not accessible through client side script.",
        Severity: "Info",
        URLs: []URLsFieldType{URLs},
        FurtherInfo: []FurtherInfoFieldType{FURTHER_INFO},
    }
    reportIssue(issue)
}


// credit: http://stackoverflow.com/a/14765076/1253487
func splitByRegex(text string, delimeter string) []string {
    reg := regexp.MustCompile(delimeter)
    indexes := reg.FindAllStringIndex(text, -1)
    laststart := 0
    result := make([]string, len(indexes) + 1)
    for i, element := range indexes {
            result[i] = text[laststart:element[0]]
            laststart = element[1]
    }
    result[len(indexes)] = text[laststart:len(text)]
    return result
}

func hasValue(list []string, value string) bool {
    for _, element := range list {
        if element == value {
            return true
        }
    }
    return false
}

func reportIssue(issue *Issue) {
   b, err := json.Marshal(issue)
    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Println(string(b))
}

func scanSetCookieHeader(url string) {
    found_risk := false

    response, err := http.Get(url)
    if err != nil {
        return  // TODO: error handling
    } else {
        // first check if 'set-cookie' is present
        h_value := response.Header.Get("Set-Cookie")
        if h_value == "" {
            reportNoSetCookie()
        } else {
            val_list := splitByRegex(h_value, `\s*;\s*`)
 
            if !hasValue(val_list, "secure") {
                reportNoSecureFlag(h_value)
                found_risk = true
            }

            if !hasValue(val_list, "HttpOnly") {
                reportNoHttpOnlyFlag(h_value)
                found_risk = true
            }

            if !found_risk {
                reportBothFlagsFound()
            }
        }
    }
        
        
}


func main() {
    
    // checks url parameter is passed
    if len(os.Args) < 2 {
        fmt.Println("URL missing from the command-line parameter list.")
    } else {
        // assume the second parameter is a URL
        url := os.Args[1]
        scanSetCookieHeader(url)
    }
}
