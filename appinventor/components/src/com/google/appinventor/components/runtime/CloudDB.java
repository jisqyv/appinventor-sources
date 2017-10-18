// -*- mode: java; c-basic-offset: 2; -*-
// Copyright 2015 MIT, All rights reserved
// Released under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

//Natalie: Package should be different for an extension
package com.google.appinventor.components.runtime;

import android.app.Activity;

import android.content.ContentValues;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

import android.net.ConnectivityManager;
import android.net.NetworkInfo;

import android.os.Environment;
import android.os.Handler;

import android.util.Base64;
import android.util.Log;

import com.google.appinventor.components.annotations.DesignerComponent;
import com.google.appinventor.components.annotations.DesignerProperty;
import com.google.appinventor.components.annotations.PropertyCategory;
import com.google.appinventor.components.annotations.SimpleEvent;
import com.google.appinventor.components.annotations.SimpleFunction;
import com.google.appinventor.components.annotations.SimpleProperty;
import com.google.appinventor.components.annotations.UsesBroadcastReceivers;
import com.google.appinventor.components.annotations.UsesLibraries;
import com.google.appinventor.components.annotations.UsesPermissions;
import com.google.appinventor.components.annotations.androidmanifest.ActionElement;
import com.google.appinventor.components.annotations.androidmanifest.IntentFilterElement;
import com.google.appinventor.components.annotations.androidmanifest.ReceiverElement;

import com.google.appinventor.components.common.ComponentCategory;
import com.google.appinventor.components.common.PropertyTypeConstants;

import com.google.appinventor.components.runtime.errors.YailRuntimeError;

import com.google.appinventor.components.runtime.util.CloudDBJedisListener;
import com.google.appinventor.components.runtime.util.JsonUtil;
import com.google.appinventor.components.runtime.util.YailList;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import org.json.JSONArray;
import org.json.JSONException;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.exceptions.JedisConnectionException;
import redis.clients.jedis.exceptions.JedisDataException;
import redis.clients.jedis.exceptions.JedisException;

/**
 * The CloudDB component stores and retrieves information in the Cloud using Redis, an
 * open source library. The component has methods to store a value under a tag and to
 * retrieve the value associated with the tag. It also possesses a listener to fire events
 * when stored values are changed. It also posseses a sync capability which helps CloudDB
 * to sync with data collected offline.
 *
 * @author manting@mit.edu (Natalie Lao)
 * @author joymitro1989@gmail.com (Joydeep Mitra)
 */

@DesignerComponent(version = 1,
    description = "Non-visible component that communicates with CloudDB server to store" +
        " and retrieve information.",
    designerHelpDescription = "Non-visible component that communicates with CloudDB " +
        "server to store and retrieve information.",
    category = ComponentCategory.EXPERIMENTAL,
    nonVisible = true,
    iconName = "images/cloudDB.png")
// Commented out by JIS 10/18/2017 -- First Version of CloudDB will not have offline support
/* @UsesBroadcastReceivers(receivers = {
        @ReceiverElement(name = "com.google.appinventor.components.runtime.util.AddReceiver",
                intentFilters = {
                        @IntentFilterElement(actionElements = {
                                @ActionElement(name = "com.evernote.android.job.ADD_JOB_CREATOR")})
                },
                exported = "false"),
        @ReceiverElement(name = "com.evernote.android.job.v14.PlatformAlarmReceiver",
                intentFilters = {
                        @IntentFilterElement(actionElements = {
                                @ActionElement(name = "com.evernote.android.job.v14.RUN_JOB"),
                                @ActionElement(name = "net.vrallev.android.job.v14.RUN_JOB")})
                },
                exported = "false"),
        @ReceiverElement(name = "com.evernote.android.job.JobBootReceiver",
                intentFilters = {
                        @IntentFilterElement(actionElements = {
                                @ActionElement(name = "android.intent.action.BOOT_COMPLETED"),
                                @ActionElement(name = "android.intent.action.QUICKBOOT_POWERON"),
                                @ActionElement(name = "com.htc.intent.action.QUICKBOOT_POWERON"),
                                @ActionElement(name = "android.intent.action.MY_PACKAGE_REPLACED")})
                },
                exported = "false")
}) */
@UsesPermissions(permissionNames = "android.permission.INTERNET," +
//                 "android.permission.WAKE_LOCK," +
//                 "android.permission.RECEIVE_BOOT_COMPLETED," +
                   "android.permission.ACCESS_NETWORK_STATE")

@UsesLibraries(libraries = "jedis.jar")
public final class CloudDB extends AndroidNonvisibleComponent implements Component {
  private static final String LOG_TAG = "CloudDB";
  private static final String BINFILE_DIR = "/AppInventorBinaries";
  private boolean importProject = false;
  private String projectID = "";
  private String token = "";
  private boolean isPublic = false;
  // Note: The two variables below are static because the systems they
  // interact with within CloudDB are also static Note: Natalie check true
  private static boolean isInitialized = false;  // Whether we have made our first
                                                 // connection to Firebase
  private static boolean persist = false;        // Whether or not we are in persistant mode
                                                 // where variables are kept when an app exits
                                                 // when off-line

  private String defaultRedisServer = null;
  private boolean useDefault = true;

  private Handler androidUIHandler;
  private final Activity activity;
  private CloudDBJedisListener childListener;

  private Jedis INSTANCE = null;
  private String redisServer = "DEFAULT";
  private int redisPort;
  private volatile boolean LISTENERSTOPPING = false;

  // To avoid blocking the UI thread, we do most Jedis operations in the background.
  // Rather then spawning a new thread for each request, we use an ExcutorService with
  // a single background thread to perform all the Jedis work. Using a single thread
  // also means that we can share a single Jedis connection and not worry about thread
  // synchronization.

  private ExecutorService background = Executors.newSingleThreadExecutor();

  //added by Joydeep Mitra
  private boolean sync = false;
  private long syncPeriod = 9_00_000;
  private ConnectivityManager cm;
  //private CloudDBCacheHelper cloudDBCacheHelper;
  //-------------------------

  // ReturnVal -- Holder which can be used as a final value but whose content
  //              remains mutable.
  private static class ReturnVal {
    String err;                 // Holder for any errors
    Object retval;              // Returned value

    Object getRetval() {
      return retval;
    }

  }

  //Natalie: What does this do?
  private abstract static class Transactional {
    final Object arg1;
    final Object arg2;
    final ReturnVal retv;

    Transactional(Object arg1, Object arg2, ReturnVal retv) {
      this.arg1 = arg1;
      this.arg2 = arg2;
      this.retv = retv;
    }

    ReturnVal getResult() {
      return retv;
    }
  }

  /**
   * Creates a new CloudDB component.
   * @param container the Form that this component is contained in.
   */
  public CloudDB(ComponentContainer container) {
    super(container.$form());
    // We use androidUIHandler when we set up operations that run asynchronously
    // in a separate thread, but which themselves want to cause actions
    // back in the UI thread.  They do this by posting those actions
    // to androidUIHandler.
    androidUIHandler = new Handler();
    Log.d(LOG_TAG, "Static: androidUIHandler = " + androidUIHandler);
    this.activity = container.$context();
    //Defaults set in MockCloudDB.java in appengine/src/com/google/appinventor/client/editor/simple/components
    projectID = ""; // set in Designer
    token = ""; //set in Designer

    redisPort = 9001;
    cm = (ConnectivityManager) form.$context().getSystemService(android.content.Context.CONNECTIVITY_SERVICE);
  }

  /**
   * Initialize: Do runtime initialization of CloudDB
   */
  public void Initialize() {
    Log.i(LOG_TAG, "Initalize called!");
    isInitialized = true;
    startListener();
  }

  private void stopListener() {
    // We do this on the UI thread to make sure it is complete
    // before we repoint the redis server (or port)
    Log.i(LOG_TAG, "Listener stopping!");
    LISTENERSTOPPING = true;
    Jedis jedis = getJedis();
    try {
      jedis.psubscribe(new CloudDBJedisListener(CloudDB.this), "__key*__:*");
    } catch (Exception e) {
      Log.e(LOG_TAG, "in stop listener", e);
      flushJedis();
    }
    if (INSTANCE != null) {     // Close the default instance for non-pubsub
      INSTANCE.quit();          // because we always call this when we are likely
      INSTANCE = null;          // to change the redis server we are using
    }
  }

  private void startListener() {
    // Retrieve new posts as they are added to the CloudDB.
    // Note: We use a real thread here rather then the background executor
    // because this thread will run effectively forever
    LISTENERSTOPPING = false;
    Log.i(LOG_TAG, "Listener starting!");
    Thread t = new Thread() {
        public void run() {
          while (true) {
            Jedis jedis = getJedis(true);
            if (jedis != null) {
              try {
                jedis.psubscribe(new CloudDBJedisListener(CloudDB.this), "__key*__:*");
              } catch (Exception e) {
                Log.e(LOG_TAG, "Error in listener thread", e);
                try {
                  jedis.close();
                } catch (Exception ee) {
                  // XXX
                }
                try {
                  Thread.sleep(1000);
                } catch (InterruptedException ee) {
                  // XXX
                }
                startListener(); // Make a new attempt...(in a new thread)
                return;          // Done with this thread
              }
            } else {
              // Could not connect to the Redis server. Sleep for
              // a minute and try again. Note: We can sleep because
              // we are in a separate thread.
              Log.i(LOG_TAG, "Cannot connect to Redis server, sleeping 1 minute...");
              try {
                Thread.sleep(60*1000);
              } catch (InterruptedException e) {
                // XXX
              }
            }
            if (LISTENERSTOPPING) {
              break;
            }
          }
          Log.d(LOG_TAG, "Listener existing");
        }
      };
    t.start();
  }

  @DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_STRING,
    defaultValue = "DEFAULT")
  public void RedisServer(String servername) {
    if (servername.equals("DEFAULT")) {
      if (!useDefault) {
        stopListener();
        useDefault = true;
        if (defaultRedisServer == null) { // Not setup yet
          Log.d(LOG_TAG, "RedisServer called default defaultServer (should not happen!)");
        } else {
          redisServer = defaultRedisServer;
          startListener();
        }
      }
    } else {
      useDefault = false;
      if (!servername.equals(redisServer)) {
        stopListener();
        redisServer = servername;
        startListener();
      }
    }
  }

  @SimpleProperty(category = PropertyCategory.BEHAVIOR,
      description = "The Redis Server to use.")
  public String RedisServer() {
    if (redisServer.equals(defaultRedisServer)) {
      return "DEFAULT";
    } else {
      return redisServer;
    }
  }

  // This is a non-documented property because it is hidden in the
  // UI. Its purpose in life is to transmit the default redis server
  // from the system into the Companion or packaged app. The Default
  // server is set in appengine-web.xml (the clouddb.server property). It
  // is sent to the client from the server via the system config call.

  @DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_STRING)
  @SimpleProperty(category = PropertyCategory.BEHAVIOR,
    description = "The Default Redis Server to use.",
    userVisible = false)
  public void DefaultRedisServer(String server) {
    defaultRedisServer = server;
    if (useDefault) {
      redisServer = server;
//      stopListener();
    }
  }

  @DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_INTEGER,
    defaultValue = "9001")
  public void RedisPort(int port) {
    stopListener();
    redisPort = port;
    startListener();
  }

  @SimpleProperty(category = PropertyCategory.BEHAVIOR,
      description = "The Redis Server port to use.")
  public int RedisPort() {
    return redisPort;
  }

  /**
   * Getter for the ProjectID.
   *
   * @return the ProjectID for this CloudDB project
   */
  @SimpleProperty(category = PropertyCategory.BEHAVIOR,
      description = "Gets the ProjectID for this CloudDB project.")
  public String ProjectID() {
    checkProjectIDNotBlank();
    return projectID;
  }

  /**
   * Specifies the ID of this CloudDB project.
   *
   * @param id the project ID
   */
  @DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_STRING,
      defaultValue = "")
  public void ProjectID(String id) {
    if (!projectID.equals(id)) {
      projectID = id;
    }
    if (projectID.equals("")){
      throw new RuntimeException("CloudDB ProjectID property cannot be blank.");
    }
  }

  /**
   * Specifies the Token Signature of this CloudDB project.
   *
   * @param authToken for CloudDB server
   */
  @DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_STRING,
          defaultValue = "")
  public void Token(String authToken) {
    if (!token.equals(authToken)) {
      token = authToken;
    }
    if (token.equals("")){
      throw new RuntimeException("CloudDB Token property cannot be blank.");
    }
  }

  /**
   * Getter for the authTokenSignature.
   *
   * @return the authTokenSignature for this CloudDB project
   */
  @SimpleProperty(category = PropertyCategory.BEHAVIOR, userVisible = false,
          description = "Gets the token for this CloudDB project.")
  public String Token() {
    checkProjectIDNotBlank();
    return token;
  }

  // @SimpleFunction
  // public void PerformSyncNow(){
  //   SyncJob.scheduleSync();
  // }

  /**
   * Asks CloudDB to store the given value under the given tag.
   *
   * @param tag The tag to use
   * @param valueToStore The value to store. Can be any type of value (e.g.
   * number, text, boolean or list).
   */
  @SimpleFunction
  public void StoreValue(final String tag, final Object valueToStore) {
    Log.i("CloudDB","StoreValue");
    checkProjectIDNotBlank();
    Log.i("CloudDB","PASSSSS");

    final String value;
    NetworkInfo networkInfo = cm.getActiveNetworkInfo();
    boolean isConnected = networkInfo != null && networkInfo.isConnected();

    try {
      if (valueToStore != null) {
        String strval = valueToStore.toString();
        if (strval.startsWith("file:///") || strval.startsWith("/storage")) {
          value = JsonUtil.getJsonRepresentation(readFile(strval));
        } else {
          value = JsonUtil.getJsonRepresentation(valueToStore);
        }
      } else {
        value = "";
      }
    } catch(JSONException e) {
      throw new YailRuntimeError("Value failed to convert to JSON.", "JSON Creation Error.");
    }

    //Natalie: perform the store operation
    //valueToStore is always converted to JSON (String);
    if (isConnected) {
      Log.i("CloudDB","Device is online...");
      background.submit(new Runnable() {
          public void run() {
            try {
              Jedis jedis = getJedis();
              Log.i("CloudDB", "Before set is called...");
              String statusCodeReply = jedis.set(projectID+tag,value);
              Log.i("CloudDB", "Jedis Key = " + projectID+tag);
              Log.i("CloudDB", "Jedis Val = " + value);
            } catch (JedisException e) {
              CloudDBError(e.getMessage());
              flushJedis();
            }
          }
        });
    } else {
      CloudDBError("Cannot store values off-line.");
    }
    Log.i("CloudDB", "End of StoreValue...");
  }

  /**
   * GetValue asks CloudDB to get the value stored under the given tag.
   * It will pass valueIfTagNotThere to GotValue if there is no value stored
   * under the tag.
   *
   * @param tag The tag whose value is to be retrieved.
   * @param valueIfTagNotThere The value to pass to the event if the tag does
   *                           not exist.
   */
  @SimpleFunction
  public void GetValue(final String tag, final Object valueIfTagNotThere) {
    checkProjectIDNotBlank();
    Log.d(CloudDB.LOG_TAG,"getting value ...");
    final AtomicReference<Object> value = new AtomicReference<Object>();
    Cursor cursor = null;
    SQLiteDatabase db = null;
    NetworkInfo networkInfo = cm.getActiveNetworkInfo();
    boolean isConnected = networkInfo != null && networkInfo.isConnected();

    if (isConnected) {
      // Set value to either the JSON from the CloudDB
      // or the JSON representation of valueIfTagNotThere
      background.submit(new Runnable() {
          public void run() {
            Jedis jedis = getJedis();
            try {
              Log.d(CloudDB.LOG_TAG,"reading from Redis ...");
              String returnValue = jedis.get(projectID+tag);
              // Set<String> returnValues = jedis.zrange(projectID+tag,0,-1);
              // Log.d(CloudDB.LOG_TAG,"zrange success ...");
              // String returnValue = null;
              // if(returnValues != null && !returnValues.isEmpty()){
              //   returnValue = returnValues.toArray()[returnValues.size()-1].toString();
              // }
              Log.d(CloudDB.LOG_TAG,"Device is online = " + returnValue);
              if (returnValue != null) {
                String val = getJsonRepresenationIfValueFileName(returnValue);
                if(val != null) value.set(val);
                else value.set(returnValue);
              }
              else {
                Log.d(CloudDB.LOG_TAG,"Value retrieved is null");
                value.set(JsonUtil.getJsonRepresentation(valueIfTagNotThere));
              }
            } catch (JSONException e) {
              throw new YailRuntimeError("Value failed to convert to JSON.", "JSON Creation Error.");
            } catch (NullPointerException e) {
              Log.d(CloudDB.LOG_TAG,"error while zrange...");
              flushJedis();
              throw new YailRuntimeError("set threw a runtime exception.", "Redis runtime exception.");
            } catch (JedisException e) {
              CloudDBError(e.getMessage());
              flushJedis();
            }

            androidUIHandler.post(new Runnable() {
                public void run() {
                  // Signal an event to indicate that the value was
                  // received.  We post this to run in the Application's main
                  // UI thread.
                  GotValue(tag, value.get());
                }
              });
          }
        });
    } else {
      CloudDBError("Cannot fetch variables while off-line.");
    }
  }

  @SimpleEvent(description = "Event triggered by the \"RemoveFirstFromList\" function. The " +
    "argument \"value\" is the object that was the first in the list, and which is now " +
    "removed.")
  public void FirstRemoved(Object value) {
    Log.d(CloudDB.LOG_TAG, "FirstRemoved: Value = " + value);
    checkProjectIDNotBlank();
    final CloudDB me = this;
    try {
      if(value != null && value instanceof String) {
        value = JsonUtil.getObjectFromJson((String) value);
      }
    } catch (JSONException e) {
      Log.e(CloudDB.LOG_TAG,"error while converting to JSON...",e);
      return;
    }
    final Object sValue = value;
    androidUIHandler.post(new Runnable() {
        @Override
        public void run() {
          EventDispatcher.dispatchEvent(me, "FirstRemoved", sValue);
        }
      });
  }

  private static final String POP_FIRST_SCRIPT =
      "local key = KEYS[1];" +
      "local currentValue = redis.call('get', key);" +
      "local decodedValue = cjson.decode(currentValue);" +
      "if (type(decodedValue) == 'table') then " +
      "  local removedValue = table.remove(decodedValue, 1);" +
      "  local newValue = cjson.encode(decodedValue);" +
      "  redis.call('set', key, newValue);" +
      "  return removedValue;" +
      "else " +
      "  return error('You can only remove elements from a list');" +
      "end";

  @SimpleFunction(description = "Return the first element of a list and atomically remove it. " +
    "If two devices use this function simultaneously, one will get the first element and the " +
    "the other will get the second element, or an error if there is no available element. " +
    "When the element is available, the \"FirstRemoved\" event will be triggered.")
  public void RemoveFirstFromList(final String tag) {
    checkProjectIDNotBlank();

    final String key = projectID + tag;

    background.submit(new Runnable() {
        public void run() {
          Jedis jedis = getJedis();
          try {
            FirstRemoved(jedis.eval(POP_FIRST_SCRIPT, 1, key));
          } catch (JedisException e) {
            CloudDBError(e.getMessage());
            flushJedis();
          }
        }
      });
  }

  private static final String APPEND_SCRIPT =
      "local key = KEYS[1];" +
      "local toAppend = ARGV[1];" +
      "local currentValue = redis.call('get', key);" +
      "local newTable;" +
      "if (currentValue == false) then " +
      "  newTable = {};" +
      "else " +
      "  newTable = cjson.decode(currentValue);" +
      "  if not (type(newTable) == 'table') then " +
      "    return error('You can only append to a list');" +
      "  end " +
      "end " +
      "table.insert(newTable, toAppend);" +
      "local newValue = cjson.encode(newTable);" +
      "redis.call('set', key, newValue);" +
      "return redis.call('get', key);";

  @SimpleFunction(description = "Append a value to the end of a list atomically. " +
    "If two devices use this function simultaneously, both will be appended and no " +
    "data lost.")
  public void AppendValueToList(final String tag, final Object itemToAdd) {
    checkProjectIDNotBlank();

    Object itemObject = new Object();
    try {
      if(itemToAdd != null) {
        itemObject = JsonUtil.getJsonRepresentation(itemToAdd);
      }
    } catch(JSONException e) {
      throw new YailRuntimeError("Value failed to convert to JSON.", "JSON Creation Error.");
    }

    final String item = (String) itemObject;
    final String key = projectID + tag;

    background.submit(new Runnable() {
        public void run() {
          Jedis jedis = getJedis();
          try {
            jedis.eval(APPEND_SCRIPT, 1, key, item);
          } catch(JedisException e) {
            CloudDBError(e.getMessage());
            flushJedis();
          }
        }
      });
  }

  /**
   * Indicates that a GetValue request has succeeded.
   *
   * @param value the value that was returned. Can be any type of value
   *              (e.g. number, text, boolean or list).
   */
  @SimpleEvent
  public void GotValue(String tag, Object value) {
    Log.d(CloudDB.LOG_TAG, "GotValue: tag = " + tag + " value = " + (String) value);
    checkProjectIDNotBlank();

    // We can get a null value is the Jedis connection failed in some way.
    // not sure what to do here, so we'll signal an error for now.
    if (value == null) {
      CloudDBError("Trouble getting " + tag + " from the server.");
      return;
    }

    try {
      Log.d(LOG_TAG, "GotValue: Class of value = " + value.getClass().getName());
      if(value != null && value instanceof String) {
        value = JsonUtil.getObjectFromJson((String) value);
      }
    } catch(JSONException e) {
      throw new YailRuntimeError("Value failed to convert from JSON.", "JSON Retrieval Error.");
    }

    // Invoke the application's "GotValue" event handler
    EventDispatcher.dispatchEvent(this, "GotValue", tag, value);
  }

  /**
   * Asks CloudDB to forget (delete or set to "null") a given tag.
   *
   * @param tag The tag to remove
   */
  @SimpleFunction(description = "Remove the tag from Firebase")
  public void ClearTag(final String tag) {
    //Natalie: Should we also add ClearTagsList? Jedis can delete a list of tags easily
    checkProjectIDNotBlank();
    try {
      Jedis jedis = getJedis();
      jedis.del(projectID+tag);
    } catch (Exception e) {
      CloudDBError(e.getMessage());
      flushJedis();
    }
  }

  /**
   * GetTagList asks CloudDB to retrieve all the tags belonging to this project.
   *
   * The resulting list is returned in GotTagList
   */
  @SimpleFunction(description = "Get the list of tags for this application. " +
      "When complete a \"TagList\" event will be triggered with the list of " +
      "known tags.")
  public void GetTagList() {
    //Natalie: Need Listener here too!
    checkProjectIDNotBlank();
    NetworkInfo networkInfo = cm.getActiveNetworkInfo();
    boolean isConnected = networkInfo != null && networkInfo.isConnected();
    if (isConnected) {
      background.submit(new Runnable() {
          public void run() {

            Jedis jedis = getJedis();
            Set<String> value = null;
            try {
              value = jedis.keys(projectID+"*");
            } catch (JedisException e) {
              CloudDBError(e.getMessage());
              flushJedis();
              return;
            }
            final List<String> listValue = new ArrayList<String>(value);

            for(int i = 0; i < listValue.size(); i++){
              listValue.set(i, listValue.get(i).substring((projectID).length()));
            }

            androidUIHandler.post(new Runnable() {
                @Override
                public void run() {
                  TagList(listValue);
                }
              });
          }
        });
    } else {
      CloudDBError("Not connected to the Internet, cannot list tags");
    }
  }

  /**
   * Indicates that a GetTagList request has succeeded.
   *
   * @param value the list of tags that was returned.
   */
  @SimpleEvent(description = "Event triggered when we have received the list of known tags. " +
      "Used with the \"GetTagList\" Function.")
  public void TagList(List<String> value) {
    // Natalie: Why is this not called "GotTagList"? Also need to only
    // show tag without or projectID
    checkProjectIDNotBlank();
    EventDispatcher.dispatchEvent(this, "TagList", value);
  }

  /**
   * Indicates that the data in the CloudDB project has changed.
   * Launches an event with the tag and value that have been updated.
   *
   * @param tag the tag that has changed.
   * @param value the new value of the tag.
   */
  @SimpleEvent
  public void DataChanged(final String tag, final Object value) {
    androidUIHandler.post(new Runnable() {
      public void run() {
        Object tagValue = "";
        try {
          if(value != null && value instanceof String) {
            tagValue = JsonUtil.getObjectFromJson((String) value);
            System.out.println(tagValue);
          }
        } catch(JSONException e) {
          throw new YailRuntimeError("Value failed to convert from JSON.", "JSON Retrieval Error.");
        }

        String parsedTag = tag.substring(projectID.length());

        // Invoke the application's "DataChanged" event handler
        EventDispatcher.dispatchEvent(CloudDB.this, "DataChanged", parsedTag, tagValue);
      }
    });
  }

  /**
   * Indicates that the communication with the CloudDB signaled an error.
   *
   * @param message the error message
   */
  @SimpleEvent
  public void CloudDBError(final String message) {
    // Log the error message for advanced developers
    Log.e(LOG_TAG, message);
    final CloudDB me = this;
    androidUIHandler.post(new Runnable() {
        @Override
        public void run() {

          // Invoke the application's "CloudDBError" event handler
          boolean dispatched = EventDispatcher.dispatchEvent(me, "CloudDBError", message);
          if (!dispatched) {
            // If the handler doesn't exist, then put up our own alert
            Notifier.oneButtonAlert(form, message, "CloudDBError", "Continue");
          }
        }
      });
  }

  private void checkProjectIDNotBlank(){
    if (projectID.equals("")){
      throw new RuntimeException("CloudDB ProjectID property cannot be blank.");
    }
    if(token.equals("")){
      throw new RuntimeException("CloudDB Token property cannot be blank");
    }
  }

  private Jedis getJedis(boolean createNew) {
    Jedis jedis;
    try {
      Log.d(LOG_TAG, "getJedis(true): Attempting a new connection.");
      jedis = new Jedis(redisServer, redisPort);
      Log.d(LOG_TAG, "getJedis(true): Have new connection.");
      jedis.auth(token);
      Log.d(LOG_TAG, "getJedis(true): Authentication complete.");
    } catch (JedisConnectionException e) {
      CloudDBError(e.getMessage());
      return null;
    }
    return jedis;
  }

  public Jedis getJedis() {
    if (INSTANCE == null) {
      INSTANCE = getJedis(true);
    }
    return INSTANCE;
  }

  /*
   * flushJedis -- Flush the singleton jedis connection. This is
   * used when we detect an error from jedis. It is possible that after
   * an error the jedis connection is in an invalid state (or closed) so
   * we want to make sure we get a new one the next time around!
   */

  public void flushJedis() {
    if (INSTANCE == null) {
      return;                   // Nothing to do
    }
    try {
      INSTANCE.close();         // Just in case we still have
                                // a connection
    } catch (Exception e) {
      // XXX
    }
    INSTANCE = null;
    stopListener();             // This is probably hosed to, so restart
    startListener();
  }

 /**
   * Accepts a file name and returns a Yail List with two
   * elements. the first element is the file's extension (example:
   * jpg, gif, etc.). The second element is the base64 encoded
   * contents of the file. This function is suitable for reading
   * binary files such as sounds and images. The base64 contents can
   * then be stored with mechanisms oriented around text, such as
   * tinyDB, Fusion tables and Firebase.
   *
   * Written by Jeff Schiller (jis) for the BinFile Extension
   *
   * @param fileName
   * @returns YailList the list of the file extension and contents
   */
  private YailList readFile(String fileName) {
    try {
      String originalFileName = fileName;
      // Trim off file:// part if present
      if (fileName.startsWith("file://")) {
        fileName = fileName.substring(7);
      }
      if (!fileName.startsWith("/")) {
        throw new YailRuntimeError("Invalid fileName, was " + originalFileName, "ReadFrom");
      }
      File inputFile = new File(fileName);
      if (!inputFile.isFile()) {
        throw new YailRuntimeError("Cannot find file", "ReadFrom");
      }
      String extension = getFileExtension(fileName);
      FileInputStream inputStream = new FileInputStream(inputFile);
      byte [] content = new byte[(int)inputFile.length()];
      int bytesRead = inputStream.read(content);
      if (bytesRead != inputFile.length()) {
        throw new YailRuntimeError("Did not read complete file!", "Read");
      }
      inputStream.close();
      String encodedContent = Base64.encodeToString(content, Base64.DEFAULT);
      Object [] results = new Object[2];
      results[0] = "." + extension;
      results[1] = encodedContent;
      return YailList.makeList(results);
    } catch (FileNotFoundException e) {
      throw new YailRuntimeError(e.getMessage(), "Read");
    } catch (IOException e) {
      throw new YailRuntimeError(e.getMessage(), "Read");
    }
  }

  /**
   * Accepts a base64 encoded string and a file extension (which must be three characters).
   * Decodes the string into a binary and saves it to a file on external storage and returns
   * the filename assigned.
   *
   * Written by Jeff Schiller (jis) for the BinFile Extension
   *
   * @param input Base64 input string
   * @param fileExtension three character file extension
   * @return the name of the created file
   */
  private String writeFile(String input, String fileExtension) {
    try {
      if (fileExtension.length() != 3) {
        throw new YailRuntimeError("File Extension must be three characters", "Write Error");
      }
      byte [] content = Base64.decode(input, Base64.DEFAULT);
      String fullDirName = Environment.getExternalStorageDirectory() + BINFILE_DIR;
      File destDirectory = new File(fullDirName);
      destDirectory.mkdirs();
      File dest = File.createTempFile("BinFile", "." + fileExtension, destDirectory);
      FileOutputStream outStream = new FileOutputStream(dest);
      outStream.write(content);
      outStream.close();
      String retval = dest.toURI().toASCIIString();
      trimDirectory(20, destDirectory);
      return retval;
    } catch (Exception e) {
      throw new YailRuntimeError(e.getMessage(), "Write");
    }
  }

  // keep only the last N files, where N = maxSavedFiles
  // Written by Jeff Schiller (jis) for the BinFile Extension
  private void trimDirectory(int maxSavedFiles, File directory) {

    File [] files = directory.listFiles();

    Arrays.sort(files, new Comparator<File>(){
      public int compare(File f1, File f2)
      {
        return Long.valueOf(f1.lastModified()).compareTo(f2.lastModified());
      } });

    int excess = files.length - maxSavedFiles;
    for (int i = 0; i < excess; i++) {
      files[i].delete();
    }

  }

  // Utility to get the file extension from a filename
  // Written by Jeff Schiller (jis) for the BinFile Extension
  private String getFileExtension(String fullName) {
    String fileName = new File(fullName).getName();
    int dotIndex = fileName.lastIndexOf(".");
    return dotIndex == -1 ? "" : fileName.substring(dotIndex + 1);
  }

  /*
  * Written by joymitro@gmail.com (Joydeep Mitra)
  * This method converts a file path to a JSON representation.
  * The code in the method was part of GetValue. For better modularity and reusability
  * the logic is now part of this method, which can be invoked from wherever and
  * whenever required.
  *
  * @param file path
  * @return JSON representation
  */
  private String getJsonRepresenationIfValueFileName(String value){
    try {
      JSONArray valueJsonList = new JSONArray(value);
      List<String> valueList = JsonUtil.getStringListFromJsonArray(valueJsonList);
      if (valueList.size() == 2) {
        if (valueList.get(0).startsWith(".")) {
          String filename = writeFile(valueList.get(1), valueList.get(0).substring(1));
          System.out.println("Filename Written: " + filename);
          filename = filename.replace("file:/", "file:///");
          return JsonUtil.getJsonRepresentation(filename);
        } else {
          return null;
        }
      } else {
        return null;
      }
    } catch(JSONException e) {
      return null;
    }
  }

}
