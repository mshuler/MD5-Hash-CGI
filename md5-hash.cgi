#!/usr/bin/perl -w
########################################################################
# Simple CGI form to generate MD5 hashes suitable for use in /etc/shadow and an
# Apache AuthUserFile. Input is checked for strength with Data::Password and
# the hash is generated using Crypt::PasswdMD5.
#   apt-get install libdata-password-perl libcrypt-passwdmd5-perl \
#                   aspell wamerican
#   (or other language dictionaries)
#
# This allows users to maintain password secrecy and allows sysadmins to
# enforce strong passwords.  A sysadmin should never need to create, send, or
# receive a user's plain-text password; just ask the user for a hash.
#
########################################################################
# Changelog:
#
# Tue Aug 31 11:20:06 CDT 2010
# - v0.1
# - Initial release.
#
########################################################################
# License: MIT
#
# Copyright (c) 2010 Michael Shuler <michael@pbandjelly.org>
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

use strict;
use CGI::Pretty qw/:standard/;
use Data::Password qw(:all);
    # Data::Password options
    $DICTIONARY = 4;
    $FOLLOWING = 4;
    $GROUPS = 3;
    $MINLEN = 8;
    $MAXLEN = 64;
use Crypt::PasswdMD5;

print header, start_html("Generate Password Hash"),
    h2("Generate Password Hash");

if (param) {
    my $pass = param('password');

    # Weak password
    if (my $bad = IsBadPassword($pass)) {
        print p(strong("** Weak password detected.  Please, try again **"));
        print pre($bad);  # description of the fault

        # delete parameter so it doesn't get automatically filled in again
        Delete('password');
        request_password();
    }
    # Strong password - generate the hashes
    else {
        my $cryptedpass = unix_md5_crypt($pass);
        my $apachepass = apache_md5_crypt($pass);
        print p(strong("Please submit the following hashes to your systems administrator:")),
            pre("------------------ cut from here... ------------------"),
            "UNIX MD5 Hash: ", pre($cryptedpass),
            "Apache MD5 Hash: ", pre("[your_username]:$apachepass"),
            pre("------------------- ...to here -----------------------");
    }
}
else {
    request_password();
}

print br, hr;
print em("never email plain-text passwords... send hashes!");
print end_html;

sub request_password {
    print strong("Password must:"),
        ul(li("be at least ", $MINLEN, " characters"),
        li("contain a mix of lowercase, uppercase, digits, and symbols"),
        li("not contain dictionary words"),
        li("not contain keyboard groups"));
    print start_form,
            "Enter password: ",
            password_field('password'),
            submit,
        end_form;
}
# vim:set ai sw=4 ts=4 tw=0 expandtab:
