#!/bin/bash

appinventor=~/Documents/appinventor-sources/appinventor
appengine=~/Documents/appengine/appengine-java-sdk-1.8.7

cd $appinventor

ant installplay
aiDaemon &
ant
beep -l 500

$appengine/bin/dev_appserver.sh --port=8888 --address=0.0.0.0 $appinventor/appengine/build/war/