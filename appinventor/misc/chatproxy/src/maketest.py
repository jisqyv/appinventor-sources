import chat_pb2
import requests
import hmac
import hashlib

from google.protobuf.message import DecodeError

def test(question, system=None, uuid=None):
    us = chat_pb2.unsigned()
    us.huuid = 'TEST'
    eus = us.SerializeToString()
    signature = hmac.new(
        b'This is a test',
        msg=eus,
        digestmod=hashlib.sha256)
    request = chat_pb2.request()
    request.token.unsigned = eus
    request.token.signature = signature.digest()
    request.token.keyid = 1
    request.question = question
    if system:
        request.system = system
    if uuid:
        request.uuid = uuid
    z = request.SerializeToString()
    r = requests.post('http://127.0.0.1:9001/chat/v1',
                  z)
    z = chat_pb2.response()
    if r.status_code != 200:
        raise Exception("Status = %d" % r.status_code)
    global content
    content = r.content
    z.ParseFromString(r.content)
    return z
    # try:
    #     z.ParseFromString(r.content)
    # except DecodeError as err:
    #     import traceback
    #     traceback.print_exc()
    #     global derr
    #     import sys
    #     derr = sys.exc_info()
    # return z



