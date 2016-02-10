# PyCloudKit. Created on 09.02.2016
# Copyright (c) 2015 Andreas Schulz
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import print_function
import ecdsa
import base64
import hashlib
import datetime
import sys

import pycloudkit_config as cfg


def getZones(argv=None):
    # Outputs a curl command to fetch data from CloudKit.

    if not argv:
        argv = sys.argv

    # Get ISO 8601 date, cut milliseconds.
    date = datetime.datetime.utcnow().isoformat()[:-7] + 'Z'

    # Load JSON request from config.
    raw_body = ''
    _hash = hashlib.sha256(raw_body.encode('utf-8')).digest()
    body = base64.b64encode(_hash).decode('utf-8')

    # Construct URL to CloudKit container.
    web_service_url = '/database/1/' + cfg.container +\
                      '/development/public/zones/list'

    # Load API key form config.
    key_id = cfg.key_id

    # Read out certificate file corresponding to API key.
    with open('eckey.pem', 'r') as pem_file:
        signing_key = ecdsa.SigningKey.from_pem(pem_file.read())

    # Construct payload.
    unsigned_data = ':'.join([date, body, web_service_url]).encode('utf-8')

    # Sign payload via certificate.
    signed_data = signing_key.sign(unsigned_data,
                                   hashfunc=hashlib.sha256,
                                   sigencode=ecdsa.util.sigencode_der)

    signature = base64.b64encode(signed_data).decode('utf-8')

    # Construct curl command.
    output = 'curl -X GET -H "content-type: text/plain" ' +\
             '-H "X-Apple-CloudKit-Request-KeyID: ' + key_id + '" ' +\
             '-H "X-Apple-CloudKit-Request-ISO8601Date: ' + date + '" ' +\
             '-H "X-Apple-CloudKit-Request-SignatureV1: ' + signature + '" ' +\
             '-d \'' + raw_body + '\' ' +\
             'https://api.apple-cloudkit.com' + web_service_url

    print(output)


def main(argv=None):
    # Outputs a curl command to fetch data from CloudKit.

    if not argv:
        argv = sys.argv

    # Get ISO 8601 date, cut milliseconds.
    date = datetime.datetime.utcnow().isoformat()[:-7] + 'Z'

    # Load JSON request from config.
    raw_body = cfg.request
    _hash = hashlib.sha256(raw_body.encode('utf-8')).digest()
    body = base64.b64encode(_hash).decode('utf-8')

    # Construct URL to CloudKit container.
    web_service_url = '/database/1/' + cfg.container +\
                      '/development/public/records/query'

    # Load API key form config.
    key_id = cfg.key_id

    # Read out certificate file corresponding to API key.
    with open('eckey.pem', 'r') as pem_file:
        signing_key = ecdsa.SigningKey.from_pem(pem_file.read())

    # Construct payload.
    unsigned_data = ':'.join([date, body, web_service_url]).encode('utf-8')

    # Sign payload via certificate.
    signed_data = signing_key.sign(unsigned_data,
                                   hashfunc=hashlib.sha256,
                                   sigencode=ecdsa.util.sigencode_der)

    signature = base64.b64encode(signed_data).decode('utf-8')

    # Construct curl command.
    output = 'curl -X POST -H "content-type: text/plain" ' +\
             '-H "X-Apple-CloudKit-Request-KeyID: ' + key_id + '" ' +\
             '-H "X-Apple-CloudKit-Request-ISO8601Date: ' + date + '" ' +\
             '-H "X-Apple-CloudKit-Request-SignatureV1: ' + signature + '" ' +\
             '-d \'' + raw_body + '\' ' +\
             'https://api.apple-cloudkit.com' + web_service_url

    print(output)

if __name__ == '__main__':
    sys.exit(getZones(sys.argv))
