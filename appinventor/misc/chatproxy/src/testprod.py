import requests
import hmac
import hashlib

from google.protobuf.message import DecodeError

def test(question, system=None, uuid=None, provider=None, model=None, apikey=None, image=None):
    import chat_pb2
    us = chat_pb2.unsigned()
    # us.huuid = 'TEST'
    us.huuid = '103327667211985548619'
    eus = us.SerializeToString()
    signature = hmac.new(
        b'AwIRy/cNWFehWZE+nHqC1A',
        msg=eus,
        digestmod=hashlib.sha256)
    request = chat_pb2.request()
    request.token.unsigned = eus
    request.token.signature = signature.digest()
    request.token.keyid = 1
    if apikey:
        request.apikey = apikey
    if model:
        request.model = model
    if provider:
        request.provider = provider
    request.question = question
    if system:
        request.system = system
    if uuid:
        request.uuid = uuid
    if image:
        request.inputimage = image
    z = request.SerializeToString()
    r = requests.post('https://chatbot.appinventor.mit.edu/chat/v1',
                  z)
    z = chat_pb2.response()
    if r.status_code != 200:
        print(f'Error: {r.content}')
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

def dalletest(prompt, apikey=None, size="1024x1024"):
    import image_pb2
    us = image_pb2.unsigned()
    us.huuid = 'TEST'
    eus = us.SerializeToString()
    signature = hmac.new(
        b'This is a test',
        msg=eus,
        digestmod=hashlib.sha256)
    request = image_pb2.request()
    request.token.unsigned = eus
    request.token.signature = signature.digest()
    request.token.keyid = 1
    if apikey:
        request.apikey = apikey
    request.size = size
    request.prompt = prompt
    request.operation = request.OperationType.CREATE
    z = request.SerializeToString()
    r = requests.post('http://127.0.0.1:9001/image/v1',
                     z)
    # q = image_pb2.response()
    if r.status_code != 200:
        print(f'Error {r.status_code} content = {r.content}')
        return None
    z = image_pb2.response()
    z.ParseFromString(r.content)
    f = open('/ram/image.png', 'wb')
    f.write(z.image)
    f.close()

def dalleedit(prompt, apikey=None, size="1024x1024"):
    import image_pb2
    us = image_pb2.unsigned()
    us.huuid = 'TEST'
    eus = us.SerializeToString()
    signature = hmac.new(
        b'This is a test',
        msg=eus,
        digestmod=hashlib.sha256)
    request = image_pb2.request()
    request.token.unsigned = eus
    request.token.signature = signature.digest()
    request.token.keyid = 1
    request.size = size
    if apikey:
        request.apikey = apikey
    request.prompt = prompt
    request.source = open('/ram/logo.png', 'rb').read()
    request.mask = open('/ram/mask.png', 'rb').read()
    request.operation = request.OperationType.EDIT
    z = request.SerializeToString()
    r = requests.post('http://127.0.0.1:9001/image/v1',
                     z)
    # q = image_pb2.response()
    if r.status_code != 200:
        print(f'Error {r.status_code} content = {r.content}')
        return None
    z = image_pb2.response()
    z.ParseFromString(r.content)
    f = open('/ram/image.png', 'wb')
    f.write(z.image)
    f.close()



