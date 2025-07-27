# Copyright (c) 2010, Steve 'Ashcrow' Milner
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials
#      provided with the distribution.
#    * Neither the name of the project nor the names of its
#      contributors may be used to endorse or promote products
#      derived from this software without specific prior written
#      permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
"""
Simple phishtank api.
"""

__docformat__ = 'restructuredtext'
__author__ = "Steve 'Ashcrow' Milner"
__version__ = '1.0.0'
__license__ = 'New BSD'

import base64
import datetime
import json
import urllib


class PhishTankError(Exception):
    """
    Exception for PhishTank errors.
    """
    pass


class Result(object):
    """
    Result sent back from PhishTank.
    """

    # Slots for memory
    __slots__ = ['url', 'in_database', 'phish_id', 'phish_detail_page',
        'verified', 'verified_at', 'valid', 'submitted_at']

    def __init__(self, response):
        """
        Creates an instance of a response.

        :Parameters:
           - `response`: actual json response from the service
        """
        self.url = response.get('url', None)
        self.in_database = response.get('in_database', None)
        self.phish_id = response.get('phish_id', None)
        self.phish_detail_page = response.get('phish_detail_page', None)
        self.verified = response.get('verified', None)
        self.verified_at = response.get('verified_at', None)
        if self.verified_at:
            self.verified_at = self.__force_date(self.verified_at)
        self.valid = response.get('valid', None)
        self.submitted_at = response.get('submitted_at', None)
        if self.submitted_at:
            self.smubmitted_at = self.__force_date(self.submitted_at)

    def __force_date(self, date_str):
        """
        Forces a date string into a datetime object.

        :Parameters:
           - `date_str`: the date string in %Y-%m-%dT%H:%M:%S+00:00 format.
        """
        return datetime.datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S+00:00')

    def __unsafe(self):
        """
        Returns back True if known to be unsafe, False otherwise.
        """
        if self.valid:
            return True
        return False

    def __repr__(self):
        """
        Representation of thie object.
        """
        return "<Result: url=%s, unsafe=%s>" % (self.url, self.unsafe)

    def report(self):
        """
        Uses the internal data to return a report in string format.
        """
        formatted_string = ""
        for item in self.__slots__:
            if getattr(self, item):
                formatted_string += "%s: %s\n" % (item, getattr(self, item))
        formatted_string += "unsafe: %s" % self.unsafe
        return formatted_string

    # Aliases
    __str__ = report
    unicode = report

    # Properties
    unsafe = property(__unsafe)


class PhishTank(object):
    """
    PhishTank abstraction class.
    """

    _baseurl = 'http://checkurl.phishtank.com'
    _checkurl = '/checkurl/'
    __apikey = ''

    def __init__(self, apikey=None):
        """
        Create an instance of the API caller.

        :Parameters:
           - `apikey`: optional apikey to use in calls
        """
        self.__apikey = apikey

    def check(self, url):
        """
        Check a URL.

        :Parameters:
           - `url`: url to check with PhishTank
        """
        urlencoded = base64.encodestring(url)

        post_data = urllib.urlencode(
            {'url': urlencoded,
             'format': 'json',
             'app_key': self.__apikey,
            })
        con = urllib.urlopen(self._baseurl + self._checkurl, post_data)
        data = json.loads(con.read())
        if 'errortext' in data.keys():
            raise PhishTankError(data['errortext'])
        con.close()
        return Result(data['results'])
