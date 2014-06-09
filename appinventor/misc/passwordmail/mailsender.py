import pika
import sys

from message_pb2 import Message

def on_message(channel, method_frame, header_frame, body):
    sys.stderr.write("%s..." % method_frame.delivery_tag)
    m = Message.FromString(body)
    print 'New Message: email = %s, url = %s' % (m.email, m.url)
    channel.basic_ack(delivery_tag=method_frame.delivery_tag)

class _setupconsume(object):

    def __init__(self, queue, handler):
        self.queue = queue
        self.handler = handler

    def start(self, arg):
        print 'Queue %s Declared and Ready' % self.queue
        channel.basic_consume(self.handler, self.queue)

connection = pika.BlockingConnection()
channel = connection.channel()
channel.queue_declare(queue='passmail', durable=True, callback=_setupconsume('passmail', on_message).start)
channel.basic_consume(on_message, 'passmail')

try:
    channel.start_consuming()
except KeyboardInterrupt:
    channel.stop_consuming()

connection.close()
