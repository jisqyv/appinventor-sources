import pika
import sys
from email.utils import formatdate
from email.parser import Parser
import smtplib
from getpass import getpass
from email.charset import add_charset

from message_pb2 import Message

parser = Parser()
password = getpass()

def on_message(channel, method_frame, header_frame, body):
    sys.stderr.write("%s..." % method_frame.delivery_tag)
    m = Message.FromString(body)
    print 'New Message: email = %s, url = %s' % (m.email, m.url)
    sendmail(m.email, m.url)
    channel.basic_ack(delivery_tag=method_frame.delivery_tag)

class _setupconsume(object):

    def __init__(self, queue, handler):
        self.queue = queue
        self.handler = handler

    def start(self, arg):
        print 'Queue %s Declared and Ready' % self.queue
        channel.basic_consume(self.handler, self.queue)

def sendmail(email, url):
    m = parser.parsestr(template % (email, url))
    m['Date'] = formatdate(localtime=True)
    s = smtplib.SMTP('osiris.mit.edu', 587)
    s.starttls()
    s.login('jis', password)
    try:
        retval = s.sendmail('appinventor@osiris.mit.edu', [email,], str(m))
    except:
        import traceback
        traceback.print_exc()
    s.quit()

template = '''From: MIT App Inventor System <appinventor@mit.edu>
To: %s
Subject: Password Reset for you MIT App Inventor Account

You have requested a new password for your MIT App Inventor Account.
Use the link below to set (or reset) your password. After you click on
this link you will be asked to provide a new password. Once you do that
you will be logged in to App Inventor.

    Your Link is: %s

Happy Inventing!

The MIT App Inventor Team
''' #'

connection = pika.BlockingConnection()
channel = connection.channel()
channel.queue_declare(queue='passmail', durable=True, callback=_setupconsume('passmail', on_message).start)
channel.basic_consume(on_message, 'passmail')

try:
    channel.start_consuming()
except KeyboardInterrupt:
    channel.stop_consuming()

connection.close()
