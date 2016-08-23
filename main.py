#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import re
import cgi

form = """
<form method="post">
    <h1>Please enter your info:</h1>
    <table>
        <tr>
            <td class="label">
                Username:
            </td>
            <td>
                <input type="text" name="username" value="%(username)s" />
            </td>
            <td>
                <div style="color: red">%(usernameError)s</div>
            </td>
        </tr>
        <tr>
            <td class="label">
                Password:
            </td>
            <td>
                <input type="password" name="password" value="" />
            </td>
            <td>
                <div style="color: red">%(passwordError)s</div>
            </td>
        </tr>
        <tr>
            <td class="label">
                Re-enter Password:
            </td>
            <td>
                <input type="password" name="passVerify" value="" />
            </td>
            <td>
                <div style="color: red">%(passVerifyError)s</div>
            </td>
        </tr>
        <tr>
            <td class="label">
                Email (optional):
            </td>
            <td>
                <input type="text" name="email" value="%(email)s" />
            </td>
            <td>
                <div style="color: red">%(emailError)s</div>
            </td>
        </tr>
    </table>
    <input type = "submit" />
</form>
"""

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    return EMAIL_RE.match(email)

welcome = """
<h1>Welcome, %s!</h1>
"""

class Index(webapp2.RequestHandler):
    def write_form(self, username="", email="", usernameError="", passwordError="", passVerifyError="", emailError=""):
        self.response.write(form % {'username': cgi.escape(username), 'email': cgi.escape(email), 'usernameError': usernameError, 'passwordError': passwordError, 'passVerifyError': passVerifyError, 'emailError': emailError})

    def get(self):
        self.write_form()

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        passVerify = self.request.get('passVerify')
        email = self.request.get('email')
        error = False

        #check password
        if not password: #check if password is blank
            passwordError = "Password cannot be empty"
            error = True
        elif not valid_password(password): #check if password is valid
            passwordError = "Invalid Password"
            error = True
        else:
            passwordError = ""
        #check password verification
        if not passVerify: #check if password verification is blank
            passVerifyError = "Password Verification cannot be empty"
            error = True
        elif password != passVerify: #check if password matches password verification
            passVerifyError = "Passwords do not match"
            error = True
        else:
            passVerifyError = ""
        #check username
        if not username: #check if username is blank
            usernameError = "Username cannot be empty"
            error = True
        elif not valid_username(username): #check if username if valid
            usernameError = "Invalid Username"
            error = True
        else:
            usernameError = ""
        #check email
        if not email: #check if email is blank
            emailError = ""
        elif not valid_email(email): #check if email is valid
            emailError = "Invalid Email"
            error = True
        else:
            emailError = ""
        #see if any errors returned
        if error == False:
            self.redirect('/welcome?username={}'.format(username))
        else:
            self.write_form(username, email, usernameError, passwordError, passVerifyError, emailError)

class WelcomeHandler(webapp2.RequestHandler):
    def get(self):
        username = self.request.get('username')
        if not valid_username(username): #check if username if valid
            redirect('/')
        else:
            self.response.write(welcome % username)

app = webapp2.WSGIApplication([
    ('/', Index),
    ('/welcome', WelcomeHandler)
], debug=True)
