// -*- mode: java; c-basic-offset: 2; -*-
// Copyright 2015 MIT, All rights reserved
// Released under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0
//Notification Listener from: http://stackoverflow.com/questions/26406303/redis-key-expire-notification-with-jedis

package com.google.appinventor.components.runtime.util;

import android.util.Log;

import com.google.appinventor.components.runtime.CloudDB;

import java.util.Set;
import java.util.concurrent.ExecutorService;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPubSub;
import redis.clients.jedis.exceptions.JedisException;


public class CloudDBJedisListener extends JedisPubSub {
  public CloudDB cloudDB;
  private Thread myThread;
  private Jedis myJedis = null;

  public CloudDBJedisListener(CloudDB thisCloudDB){
    cloudDB = thisCloudDB;
    myThread = Thread.currentThread();
  }

  @Override
  public void onPSubscribe(String pattern, int subscribedChannels) {
    Log.i("CloudDB", "onPSubscribe "+pattern+" "+subscribedChannels);
  }

  @Override
  public void onPMessage(String pattern, final String channel, String message) {
    Log.i("CloudDB","onPMessage pattern "+pattern+", channel: "+channel+", message: "+message);
    String retval = null;
    if (message.equals("zadd")) {
      Log.i("CloudDB", "onMessage tag = " + channel);
      Jedis jedis = cloudDB.getJedis();
      Set<String> retvals = null;
      try {
        retvals = jedis.zrange(channel, 0, -1);
      } catch (JedisException e) {
        cloudDB.flushJedis();
      }
      if (retvals != null && !retvals.isEmpty()) {
        retval = retvals.toArray()[retvals.size()-1].toString();
        Log.i("CloudDB", "onPMessage: DataChanged tag = " + channel + " value = " + retval);
        cloudDB.DataChanged(channel, retval);
      }
    } else if (message.equals("set")) {
      if (myJedis == null) {
        try {
          myJedis = cloudDB.getJedis(true);
        } catch (JedisException e) {
          Log.e("CloudDB", "creating redis connection failed", e);
          return;
        }
      }
      try {
        retval = myJedis.get(channel);
        if (retval == null) {
          Log.i("CloudDB", "onPMessage: DataChanged tag = " + channel + " received a null pointer.");
        } else {
          cloudDB.DataChanged(channel, retval);
        }
      } catch (JedisException e) {
        try {
          Log.e("CloudDB", "Error on listeners private connection", e);
          myJedis.close();
        } catch (Exception ee) {
          // XXX
        }
        myJedis = null;
      }
    }
  }

  public void terminate() {
    myThread.interrupt();
  }

  //add other Unimplemented methods
}
