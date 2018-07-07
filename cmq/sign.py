#!/usr/bin/python
# -*- coding: utf-8 -*-

import binascii
import hashlib
import hmac
import sys


class Sign:
    def __init__(self, secretId, secretKey):
        self.secretId = secretId
        self.secretKey = secretKey

    def make(self, requestHost, requestUri, params,
             method='POST', sign_method='sha1'):
        new_params = {}
        for k, v in params.items():
            if method.upper() == 'POST' and str(v).startswith("@"):
                continue
            new_params[k] = v
        sorted_params = "&".join(
                            k.replace("_", ".") + "=" + str(new_params[k])
                            for k in sorted(new_params.keys())
                         )
        srcStr = method.upper() + requestHost +\
            requestUri + '?' + sorted_params

        if sys.version > '3':
            srcStr = srcStr.encode('utf8')

        if sign_method == 'sha1':
            hashed = hmac.new(
                self.secretKey, srcStr, hashlib.sha1)
        elif sign_method == 'sha256':
            hashed = hmac.new(
                self.secretKey, srcStr, hashlib.sha256)
        return binascii.b2a_base64(hashed.digest())[:-1]


def main():
    secretId = 123
    secretKey = b'xxx'
    params = {'a': 1, 'b': 2}
    sign = Sign(secretId, secretKey)
    print(sign.make('cmq-gz.api.qcloud.com', '/v2/index.php', params))


if __name__ == '__main__':
    main()
