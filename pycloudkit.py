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
import json

import pycloudkit_config as cfg

# Python version agnostic urllib imports
if sys.version_info.major < 3:
    # Python 2 (or older)
    from urllib2 import HTTPPasswordMgrWithDefaultRealm, \
        HTTPBasicAuthHandler, Request, build_opener
    from urllib import urlencode
else:
    # Python 3 (or newer)
    from urllib.request import HTTPPasswordMgrWithDefaultRealm, \
        HTTPBasicAuthHandler, Request, build_opener
    from urllib.parse import urlencode


def cloudkit_request(cloudkit_resource_url, data):
    """
    Uses HTTP GET or POST to interact with CloudKit. If data is empty, Uses
    GET, else, POSTs the data.
    """

    # Get ISO 8601 date, cut milliseconds.
    date = datetime.datetime.utcnow().isoformat()[:-7] + 'Z'

    # Load JSON request from config.
    _hash = hashlib.sha256(data.encode('utf-8')).digest()
    body = base64.b64encode(_hash).decode('utf-8')

    # Construct URL to CloudKit container.
    web_service_url = '/database/1/' + cfg.container +\
                      cloudkit_resource_url

    # Load API key from config.
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

    headers = {
        'X-Apple-CloudKit-Request-KeyID': key_id,
        'X-Apple-CloudKit-Request-ISO8601Date': date,
        'X-Apple-CloudKit-Request-SignatureV1': signature
    }

    if data:
        req_type = 'POST'
    else:
        req_type = 'GET'

    result = curl('https://api.apple-cloudkit.com' + web_service_url,
                  req_type=req_type,
                  data=data,
                  headers=headers)

    return result


def curl(url, params=None, auth=None, req_type='GET', data=None, headers=None):
    """Provides HTTP interaction like curl."""

    post_req = ['POST', 'PUT']
    get_req = ['GET', 'DELETE']

    if params is not None:
        url += '?' + urlencode(params)

    if req_type not in post_req + get_req:
        raise IOError('Wrong request type "%s" passed' % req_type)

    _headers = {}
    handler_chain = []

    if auth is not None:
        manager = HTTPPasswordMgrWithDefaultRealm()
        manager.add_password(None, url, auth['user'], auth['pass'])
        handler_chain.append(HTTPBasicAuthHandler(manager))

    if req_type in post_req and data is not None:
        _headers['Content-Length'] = len(data)

    if headers is not None:
        _headers.update(headers)

    director = build_opener(*handler_chain)

    if req_type in post_req:
        if sys.version_info.major < 3:
            _data = bytes(data)
        else:
            _data = bytes(data, encoding='utf8')
        req = Request(url, headers=_headers, data=_data)

    else:
        req = Request(url, headers=_headers)

    req.get_method = lambda: req_type
    result = director.open(req)

    return {
        'httpcode': result.code,
        'headers': result.info(),
        'content': result.read().decode('utf-8')
    }


def query_records(record_type):
    """Queries CloudKit for all records of type record_type."""
    json_query = {
        'query': {
            'recordType': record_type
        }
    }

    records = []
    while True:
        result_query_authors = cloudkit_request(
            '/development/public/records/query',
            json.dumps(json_query))
        result_query_authors = json.loads(result_query_authors['content'])

        records += result_query_authors['records']

        if 'continuationMarker' in result_query_authors.keys():
            json_query['continuationMarker'] = \
                result_query_authors['continuationMarker']
        else:
            break

    return records


def main():
    print('Requesting list of zones...')
    result_zones = cloudkit_request('/development/public/zones/list', '')
    print(result_zones['content'])

    print('Querying all authors...')
    print(query_records('Authors'))

    # new_author_data = {
    #     'operations': [{
    #         'operationType': 'create',
    #         'record': {
    #             'recordType': 'Authors',
    #             'fields': {
    #                 'firstname': {
    #                     'value': 'Andreas'
    #                 },
    #                 'lastname': {
    #                     'value': 'Schulz'
    #                 },
    #                 'title': {
    #                     'value': 'Der Azubi vom Alex'
    #                 }
    #             }
    #         }
    #     }]
    # }
    # print('Posting operation to create author...')
    # result_modify_authors = cloudkit_request(
    #     '/development/public/records/modify',
    #     json.dumps(new_author_data))
    # print(result_modify_authors['content'])

    new_quote_data = {
        'operations': [{
            'operationType': 'create',
            'record': {
                'recordType': 'Quotes',
                'fields': {
                    'text': {
                        'value': 'Ich bin ein tolles Zitat.'
                    },
                    'author': {
                        'value': {
                            'recordName': '5A3C2FFE-0A2C-4D1A-88CE-FAA4BC49E394',
                            'zoneID:': {
                                'zoneName': '_defaultZone'
                            },
                            'action': 'DELETE_SELF'
                        }
                    }
                }
            }
        }]
    }

    print('Posting operation to create quote...')
    result_modify_quotes = cloudkit_request(
        '/development/public/records/modify',
        json.dumps(new_quote_data))
    print(result_modify_quotes['content'])

if __name__ == '__main__':
    sys.exit(main())
