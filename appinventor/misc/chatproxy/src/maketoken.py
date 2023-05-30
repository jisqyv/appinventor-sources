import chat_pb2
import requests
import hmac
import hashlib
import base58

from google.protobuf.message import DecodeError

def maketoken(huuid, key):
    us = chat_pb2.unsigned()
    us.huuid = huuid
    eus = us.SerializeToString()
    signature = hmac.new(
        bytes(key, 'utf-8'),
        msg=eus,
        digestmod=hashlib.sha256)
    token = chat_pb2.token()
    token.unsigned = eus
    token.signature = signature.digest()
    stoken = base58.b58encode(token.SerializeToString())
    return str(stoken, 'utf-8')


