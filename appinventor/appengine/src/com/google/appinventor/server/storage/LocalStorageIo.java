// -*- mode: java; c-basic-offset: 2; -*-
// Copyright 2014-2015 MIT, All rights reserved.
// This is unreleased code.

package com.google.appinventor.server.storage;

import com.google.appinventor.server.CrashReport;
import com.google.appinventor.server.FileExporter;
import com.google.appinventor.server.flags.Flag;

import com.google.appinventor.server.project.youngandroid.YoungAndroidSettingsBuilder;

import com.google.appinventor.server.storage.StoredData.PWData;

import com.google.appinventor.server.util.LicenseConfig;

import com.google.appinventor.shared.rpc.AdminInterfaceException;
import com.google.appinventor.shared.rpc.BlocksTruncatedException;
import com.google.appinventor.shared.rpc.Nonce;
import com.google.appinventor.shared.rpc.admin.AdminUser;

import com.google.appinventor.shared.rpc.project.Project;
import com.google.appinventor.shared.rpc.project.ProjectSourceZip;
import com.google.appinventor.shared.rpc.project.RawFile;
import com.google.appinventor.shared.rpc.project.TextFile;
import com.google.appinventor.shared.rpc.project.UserProject;
import com.google.appinventor.shared.rpc.project.youngandroid.YoungAndroidProjectNode;

import com.google.appinventor.shared.rpc.user.SplashConfig;
import com.google.appinventor.shared.rpc.user.User;

import com.google.appinventor.shared.storage.StorageUtil;

import com.google.appinventor.shared.util.AccountUtil;

import java.io.BufferedReader;

import static com.google.appinventor.components.common.YaVersion.YOUNG_ANDROID_VERSION;
import static com.google.appinventor.shared.storage.StorageUtil.APPSTORE_CREDENTIALS_FILENAME;

import java.io.StringReader;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;

import java.nio.charset.StandardCharsets;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Properties;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.annotation.Nullable;


// Log4j
import org.apache.log4j.Logger;


/**
 * Implements the StorageIo interface using Local SQL Database and file storage.
 *
 * @author jis@mit.edu (Jeffrey I. Schiller) based on ObjectifyStorageIo.java from Sharon Perl
 *
 */
public class LocalStorageIo implements  StorageIo {
  static final Flag<Boolean> requireTos = Flag.createFlag("require.tos", false);
  static final Flag<String> storageRoot = Flag.createFlag("storage.root", "");
  static final String USER_DATABASE = storageRoot.get() + "/users.sqlite";
  static final String BUILDSTATUS_DATABASE = storageRoot.get() + "/buildstatus.sqlite";

  private static final Logger LOG = Logger.getLogger(LocalStorageIo.class);

  private static final String DEFAULT_ENCODING = "UTF-8";

  private static final long MOTD_ID = 1;

  // storage.backuptime: how long before we make a backup snapshot of a bky or scm file.
  // The time is provided in minutes but converted to milliseconds for the backuptime
  // variable. We default to 1 day.
  private static final long backupTime = Flag.createFlag("storage.backuptime",
    new Long(60*24)).get().longValue() * 60*1000;

  private Class driverClass;    // Keep the Driver class from being GC'd

  private ThreadLocal<Connection> userConn = new ThreadLocal<Connection>();
  private ThreadLocal<Connection> buildConn = new ThreadLocal<Connection>();

  // We set this to true if we are retrying a call in an error handler after
  // "fixing" the problem. This is used to handling schema upgrades. If the
  // schema is out of data, we typically get an SQLException. We then update
  // the schema and call the failing function (aka ourselves) again after
  // setting this flag. If this flag is set on an error, then something else
  // is going on and we re-throw the original error
  //
  // We do go about things in this fashion to avoid having to verify the
  // schema on each call, which would be a performance issue.
  private boolean recursiveError = false;

  // Create a final object of this class to hold a modifiable result value that
  // can be used in a method of an inner class.
  private class Result<T> {
    T t;
  }

  LocalStorageIo() {
    // Load the SQLite3 Driver Classes
    try {
      driverClass = Class.forName("org.sqlite.JDBC");
      if (storageRoot.get().equals("")) {
        throw new Exception("Invalid Storage Root");
      }
    } catch (Exception e) {
      throw CrashReport.createAndLogError(LOG, null, null, e);
    }
    checkSetup();
  }

  /**
   * Verify that we can access critical databases. If they do not exist, create them.
   *
   */
  private void checkSetup() {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
      PreparedStatement prep = conn.prepareStatement("select * from users limit 1");
      ResultSet rs = prep.executeQuery();
    } catch (SQLException e) { // Assume tables doesn't exist and create it.
      try {
        if (conn != null) {     // Let's use a new connection to create the table.
          conn.close();
          conn = null;
        }
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        conn.setAutoCommit(false);
        Statement statement = conn.createStatement();
        statement.executeUpdate("create table if not exists users (uuid string, email string, emaillower string, " +
          "visited timestamp, settings string, tosaccepted boolean, isadmin boolean, sessionid string," +
          " password string, templatepath string)");
        statement.executeUpdate("create index usersuuid on users(uuid)");
        statement.executeUpdate("create index usersemail on users(email)");
        statement.executeUpdate("create index usersemaillower on users(emaillower)");
        statement.executeUpdate("create table nonce (nonce string, userid string, projectid int, timestamp timestamp)");
        statement.executeUpdate("create index noncenonce on nonce(nonce)");
        statement.executeUpdate("create index noncedate on nonce(timestamp)");
        statement.executeUpdate("create table pwdata (uuid string, email string, timestamp timestamp)");
        statement.executeUpdate("create table rendezvous (ipaddr string, key string, timestamp timestamp)");
        statement.executeUpdate("create unique index rendkey on rendezvous (key)");
//        statement.executeUpdate("create index pwdatauuid on pwdata(uuid)");
//        statement.executeUpdate("create index pwdataemail on pwdata(email)");
        statement.executeUpdate("create table if not exists license (uuid text, hardware text, authcode text)");
        statement.close();
        conn.commit();
        conn.close();
        conn = null;
      } catch (SQLException ee) {
        throw CrashReport.createAndLogError(LOG, null, null, e);
      }
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
          throw CrashReport.createAndLogError(LOG, null, null, e);
        }
      }
    }
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
      conn.setAutoCommit(false);
      // Handle version upgrades here
      Statement statement = conn.createStatement();
      PreparedStatement prep;
      ResultSet rs;
      statement.executeUpdate("create table if not exists version (version int)");
      prep = conn.prepareStatement("select version from version");
      rs = prep.executeQuery();
      int version = 0;
      boolean doUpdate = false;
      if (rs.next()) {        // Version will be 0 if the table is empty
        version = rs.getInt("version");
      }
      prep.close();
      switch (version) {
      case 0:                 // Newly created
        statement.executeUpdate("create table splashconfig (version int, width int, height int, content text)");
        doUpdate = true;
        break;
      default:
        break;
      }
      if (doUpdate) {
        statement.executeUpdate("insert or replace into version (rowid, version) values (1, 1)");
      }
      statement.close();
      conn.commit();
      conn.close();
    } catch (SQLException ee) {
      throw CrashReport.createAndLogError(LOG, null, null, ee);
    }
    // Create the license table if it doesn't exit
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
      PreparedStatement prep = conn.prepareStatement("select * from users limit 1");
      Statement statement = conn.createStatement();
      statement.executeUpdate("create table if not exists license (uuid text, hardware text, authcode text)");
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, null, e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
          throw CrashReport.createAndLogError(LOG, null, null, e);
        }
      }
    }
    try {
      // Attempt to create the build status database
      conn = DriverManager.getConnection("jdbc:sqlite:" + BUILDSTATUS_DATABASE);
      conn.setAutoCommit(false);
      Statement statement = conn.createStatement();
      statement.executeUpdate("create table if not exists builds (userid text, projectid integer, progress integer, " +
        "used timestamp, unique (userid, projectid) on conflict replace)");
      statement.close();
      conn.commit();
      conn.close();
      conn = null;
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, null, e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
          throw CrashReport.createAndLogError(LOG, null, null, e);
        }
      }
    }
  }

  @Override
  public User getUser(String userId) {
    return getUser(userId, null);
  }

  /*
   * We return isAdmin if the UserData object has the flag set. However
   * even if we return it as false. If the user is logging in with Google
   * Credentials and the apiUser indicates they are an admin of the app,
   * then isAdmin will be set by our caller.
   */
  @Override
  public User getUser(String userId, String email) {
    return getUser(userId, email, true);
  }

  public User getUser(String userId, String email, boolean create) {
    Connection conn = null;
    ResultSet rs;
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      PreparedStatement prep;
      if (userId != null) {
        prep = conn.prepareStatement("select * from users where uuid = ?");
        prep.setString(1, userId);
      } else { // Use email address for lookup
        prep = conn.prepareStatement("select * from users where emaillower = ?");
        prep.setString(1, email.toLowerCase());
      }
      rs = prep.executeQuery();
      if (rs.next()) {
        String uuid = rs.getString("uuid");
        String zemail = rs.getString("email");
        boolean tosAccepted = rs.getBoolean("tosaccepted") || !requireTos.get();
        boolean isAdmin = rs.getBoolean("isadmin");
        String sessionId = rs.getString("sessionid");
        User retUser = new User(uuid, zemail, tosAccepted, isAdmin, sessionId);
        retUser.setPassword(rs.getString("password"));
        prep.close();
        return retUser;
      } else {
        if (userId == null) {   // Only create user if lookup was by email address
          if (create) {
            User retval = createUser(email, null, conn);
            return retval;
          }
          else {
            return null;
          }
        } else {
          return null;
        }
      }
    } catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
    }
  }

  /*
   * Note: We are passed in the SQL Connection to the User Database.
   */
  private User createUser(String email, String userId, Connection conn) throws SQLException {
    String newId;
    if (userId != null) {       // Used passed in userId (for anon account creation)
      newId = userId;
    } else {                    // If we weren't passed in a userId, create one here
      newId = UUID.randomUUID().toString();
    }
    PreparedStatement prep = conn.prepareStatement("insert into users (uuid, email, emaillower, visited," +
      " settings, tosaccepted, isadmin, sessionid, password, templatepath) " +
      "values (?, ?, ?, ?, ?, ?,?, ?, ?, ?)");
    prep.setQueryTimeout(30);
    prep.setString(1, newId);
    prep.setString(2, email);
    prep.setString(3, email.toLowerCase());
    prep.setDate(4, new java.sql.Date(System.currentTimeMillis()));
    prep.setString(5, "{}"); // settings
    prep.setBoolean(6, false);
    prep.setBoolean(7, false);
    prep.setString(8, "");
    prep.setString(9, "");
    prep.setString(10, "");
    prep.executeUpdate();
    prep.close();
    // User is created in the database. Now create the user's
    // private project directory.
    File projectPath = new File(storageRoot.get() + "/" + newId);
    projectPath.mkdir();
    Connection projectDb = null;
    try {
      projectDb = DriverManager.getConnection("jdbc:sqlite:" + storageRoot.get() + "/" + newId + "/projects.sqlite");
      Statement statement = projectDb.createStatement();
      // Note: the projectId is the rowid which is auto-created
      statement.executeUpdate("create table projects (name string, settings string, created date, modified date, history string, deleted boolean, trashed boolean, built date)");
      statement.close();
    } finally {
      if (projectDb != null) {
        projectDb.close();
      }
    }
    return new User(newId, email, false, false, "");
  }


  // Get User from email address along.
  @Override
  public User getUserFromEmail(String email) {
    return getUser(null, email);
  }

  @Override
  public void setTosAccepted(String userId) {
    Connection conn = null;
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      PreparedStatement prep = conn.prepareStatement("update users set tosaccepted = 1 where uuid = ?");
      prep.setQueryTimeout(30);
      prep.setString(1, userId);
      prep.executeUpdate();
      prep.close();
    } catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
    }
  }

  @Override
  public void setUserEmail(String userId, String email) {
    Connection conn = null;
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      PreparedStatement prep = conn.prepareStatement("update users set email = ?, emaillower = ? where uuid = ?");
      prep.setQueryTimeout(30);
      prep.setString(3, userId);
      prep.setString(1, email);
      prep.setString(2, email.toLowerCase());
      prep.executeUpdate();
      prep.close();
    } catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
    }
  }

  @Override
  public void setUserSessionId(final String userId, final String sessionId) {
    Connection conn = null;
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      PreparedStatement prep = conn.prepareStatement("update users set sessionid = ? where uuid = ?");
      prep.setQueryTimeout(30);
      prep.setString(1, sessionId);
      prep.setString(2, userId);
      prep.executeUpdate();
      prep.close();
    } catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
    }
  }

  @Override
  public void setUserPassword(String userId, String password) {
    Connection conn = null;
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      PreparedStatement prep = conn.prepareStatement("update users set password = ? where uuid = ?");
      prep.setQueryTimeout(30);
      prep.setString(1, password);
      prep.setString(2, userId);
      prep.executeUpdate();
      prep.close();
    } catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
    }
  }

  @Override
  public String loadSettings(String userId) {
    Connection conn = null;
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      PreparedStatement prep = conn.prepareStatement("select settings from users where uuid = ?");
      prep.setString(1, userId);
      ResultSet rs = prep.executeQuery();
      if (rs.next()) {
        String settings = rs.getString("settings");
        prep.close();
        return settings;
      } else {
        prep.close();
        return "";
      }
    } catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
    }
  }

  @Override
  public void storeSettings(final String userId, final String settings) {
    Connection conn = null;
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      PreparedStatement prep = conn.prepareStatement("update users set settings = ?, visited = ? where uuid = ?");
      prep.setQueryTimeout(30);
      prep.setString(1, settings);
      prep.setDate(2, new java.sql.Date(System.currentTimeMillis()));
      prep.setString(3, userId);
      prep.executeUpdate();
      prep.close();
    } catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
    }
  }

  @Override
  public long createProject(String userId, Project project,
      String projectSettings) {
    long projectId = 0;
    Connection conn = null;
    try {
      java.sql.Date now = new java.sql.Date(System.currentTimeMillis());
      // Get connection to the user's projects database
      conn = DriverManager.getConnection("jdbc:sqlite:" + storageRoot.get() + "/" + userId + "/projects.sqlite");
      conn.setAutoCommit(false);
      PreparedStatement prep = conn.prepareStatement("insert into projects (name, settings, created, modified, history, deleted, trashed) " +
        "values (?, ?, ?, ?, ?, 0, 0)");
      prep.setQueryTimeout(30);
      prep.setString(1, project.getProjectName());
      prep.setString(2, projectSettings);
      prep.setDate(3, now);
      prep.setDate(4, now);
      prep.setString(5, project.getProjectHistory());
      prep.executeUpdate();
      prep.close();
      Statement st = conn.createStatement();
      ResultSet rs = st.executeQuery("select max(rowid) as max from projects");
      if (rs.next()) {
        projectId = rs.getLong("max"); // max(rowid) is the rowid of the row we just inserted
      }
      conn.commit();            // Commit it now. If things blow out below we may
                                // wind up with a half created project so we will
                                // have to manually back out.
      rs.close();
      conn.close();
      conn = null;
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
    } finally {
      if (conn != null) {
        try {
          conn.rollback();
          conn.close();
        } catch (Exception z) {
          throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), z);
        }
      }
    }
    try {
      for (TextFile file : project.getSourceFiles()) {
        createRawFile(userId, projectId, file.getFileName(), file.getContent().getBytes(DEFAULT_ENCODING));
      }
      for (RawFile file : project.getRawSourceFiles()) {
        createRawFile(userId, projectId,  file.getFileName(), file.getContent());
      }
    } catch (IOException e) {
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
    }
    return projectId;
  }

  /*
   * Creates and populates a project file
   */
  private void createRawFile(String userId, long projectId, String fileName, byte[] content)
    throws IOException {
    FileOutputStream out = null;
    try {
      File pathName = new File(storageRoot.get() + "/" + userId + "/" + projectId + "/" + fileName);
      pathName.getParentFile().mkdirs();
      out = new FileOutputStream(pathName);
      out.write(content);
      out.close();
      out = null;
    } finally {
      if (out != null) {
        try {
          out.close();
        } catch (Exception e) {
        }
      }
    }
  }

  /**
   * Delete a project.
   *
   * We don't really delete the project. Instead we mark it as deleted but
   * leave it around so it can be recovered if it was accidentally deleted.
   * Note: Recovery requires admin action, deleted projects are invisible to
   * the end user.
   *
   * @param userId UserId of the user who owns the project
   * @param projectId projectId of the project to delete.
   */
  @Override
  public void deleteProject(String userId, long projectId) {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + storageRoot.get() + "/" + userId + "/projects.sqlite");
      PreparedStatement prep = conn.prepareStatement("update projects set deleted = 1 where rowid = ?");
      prep.setLong(1, projectId);
      prep.execute();
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null,
        collectUserProjectErrorInfo(userId, projectId), e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
          CrashReport.createAndLogError(LOG, null, collectUserProjectErrorInfo(userId, projectId), e);
        }
      }
    }
  }

  @Override
  public void setMoveToTrashFlag(final String userId, final long projectId, boolean flag) {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + storageRoot.get() + "/" + userId + "/projects.sqlite");
      PreparedStatement prep;
      if (flag) {
        prep = conn.prepareStatement("update projects set trashed = 1 where rowid = ?");
      } else {
        prep = conn.prepareStatement("update projects set trashed = 0 where rowid = ?");
      }
      prep.setLong(1, projectId);
      prep.execute();
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null,
        collectUserProjectErrorInfo(userId, projectId), e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
          CrashReport.createAndLogError(LOG, null, collectUserProjectErrorInfo(userId, projectId), e);
        }
      }
    }
  }

  @Override
  public List<Long> getProjects(final String userId) {
    List<Long> projects = new ArrayList<Long>();
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + storageRoot.get() + "/" + userId + "/projects.sqlite");
      Statement st = conn.createStatement();
      ResultSet rs = st.executeQuery("select rowid,* from projects where deleted = 0");
      while (rs.next()) {
        projects.add(rs.getLong("rowid"));
      }
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
          CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
        }
      }
    }
    return projects;
  }

  @Override
  public String loadProjectSettings(String userId, long projectId) {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + storageRoot.get() + "/" + userId + "/projects.sqlite");
      PreparedStatement prep = conn.prepareStatement("select settings from projects where rowid = ?");
      prep.setLong(1, projectId);
      ResultSet rs = prep.executeQuery();
      if (rs.next()) {
        return rs.getString("settings");
      } else {
        throw CrashReport.createAndLogError(LOG, null,
          collectUserProjectErrorInfo(userId, projectId),
          new UnauthorizedAccessException(userId, projectId, null));
      }
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null,
        collectUserProjectErrorInfo(userId, projectId), e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
          CrashReport.createAndLogError(LOG, null, collectUserProjectErrorInfo(userId, projectId), e);
        }
      }
    }
  }

  @Override
  public void storeProjectSettings(String userId, long projectId,
      String settings) {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + storageRoot.get() + "/" + userId + "/projects.sqlite");
      PreparedStatement prep = conn.prepareStatement("update projects set settings = ? where rowid = ?");
      prep.setQueryTimeout(30);
      prep.setString(1, settings);
      prep.setLong(2, projectId);
      prep.executeUpdate();
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null,
        collectUserProjectErrorInfo(userId, projectId), e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
          CrashReport.createAndLogError(LOG, null, collectUserProjectErrorInfo(userId, projectId), e);
        }
      }
    }
  }

  @Override
  public String getProjectType(final String userId, final long projectId) {
    // We only have one project type, no need to ask about it
    // Otherwise we would look up the type of project.
    return YoungAndroidProjectNode.YOUNG_ANDROID_PROJECT_TYPE;
  }

  @Override
  public UserProject getUserProject(String userId, long projectId) {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + storageRoot.get() + "/" + userId + "/projects.sqlite");
      PreparedStatement prep = conn.prepareStatement("select * from projects where rowid = ?");
      prep.setLong(1, projectId);
      ResultSet rs = prep.executeQuery();
      if (rs.next()) {
        java.sql.Date created = rs.getDate("created");
        java.sql.Date modified = rs.getDate("modified");
        java.sql.Date built = rs.getDate("built");
        boolean trashed = rs.getBoolean("trashed");
        long cmillis = 0;
        long mmillis = 0;
        long bmillis = 0;
        if (created != null) {
          cmillis = created.getTime();
        }
        if (modified != null) {
          mmillis = modified.getTime();
        }
        if (built != null) {
          bmillis = built.getTime();
        }
        return new UserProject(projectId, rs.getString("name"),
          YoungAndroidProjectNode.YOUNG_ANDROID_PROJECT_TYPE,
          cmillis, mmillis, bmillis, trashed);
      } else {
        return null;
      }
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null,
        collectUserProjectErrorInfo(userId, projectId), e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
          CrashReport.createAndLogError(LOG, null, collectUserProjectErrorInfo(userId, projectId), e);
        }
      }
    }
  }

  @Override
  public List<UserProject> getUserProjects(final String userId, final List<Long> projectIds) {
    Connection conn = null;
    List<UserProject> retval = new ArrayList();
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + storageRoot.get() + "/" + userId + "/projects.sqlite");
      Statement statement = conn.createStatement();
      ResultSet rs = statement.executeQuery("select rowid,* from projects where deleted = 0");
      while (rs.next()) {
        java.sql.Date created = rs.getDate("created");
        java.sql.Date modified = rs.getDate("modified");
        java.sql.Date built = rs.getDate("built");
        boolean trashed = rs.getBoolean("trashed");
        long cmillis = 0;
        long mmillis = 0;
        long bmillis = 0;
        if (created != null) {
          cmillis = created.getTime();
        }
        if (modified != null) {
          mmillis = modified.getTime();
        }
        if (built != null) {
          bmillis = built.getTime();
        }
        UserProject proj = new UserProject(rs.getInt("rowid"), rs.getString("name"),
          YoungAndroidProjectNode.YOUNG_ANDROID_PROJECT_TYPE,
          cmillis,
          mmillis, trashed);
        retval.add(proj);
      }
      statement.close();
      return retval;
    } catch (SQLException e) {
      if (recursiveError) {
        throw CrashReport.createAndLogError(LOG, null,
          collectUserErrorInfo(userId), e);
      } else {
        if (!updateProjectsSchema(conn)) {
          throw CrashReport.createAndLogError(LOG, null,
            collectUserErrorInfo(userId), e);
        } else {
          // Call ourselves recursively
          List<UserProject> zretVal = getUserProjects(userId, projectIds);
          // All went well, so clear the recursive error flag
          recursiveError = false;
          return zretVal;
        }
      }
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
          CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
        }
      }
    }
  }

  private String getProjectStrings(String userId, long projectId, String field) {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + storageRoot.get() + "/" + userId + "/projects.sqlite");
      PreparedStatement prep = conn.prepareStatement("select * from projects where rowid = ?");
      prep.setLong(1, projectId);
      ResultSet rs = prep.executeQuery();
      if (rs.next()) {
        return rs.getString(field);
      } else {
        return null;
      }
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null,
        collectUserProjectErrorInfo(userId, projectId), e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
          CrashReport.createAndLogError(LOG, null, collectUserProjectErrorInfo(userId, projectId), e);
        }
      }
    }
  }

  private long getProjectDates(String userId, long projectId, String field) {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + storageRoot.get() + "/" + userId + "/projects.sqlite");
      PreparedStatement prep = conn.prepareStatement("select * from projects where rowid = ?");
      prep.setLong(1, projectId);
      ResultSet rs = prep.executeQuery();
      if (rs.next()) {
        return rs.getDate(field).getTime();
      } else {
        return 0;
      }
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null,
        collectUserProjectErrorInfo(userId, projectId), e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
          CrashReport.createAndLogError(LOG, null, collectUserProjectErrorInfo(userId, projectId), e);
        }
      }
    }
  }

  @Override
  public String getProjectName(final String userId, final long projectId) {
    return getProjectStrings(userId, projectId, "name");
  }

  @Override
  public void setProjectName(String userId, long projectId, String name) {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + storageRoot.get() + "/" + userId + "/projects.sqlite");
      PreparedStatement prep = conn.prepareStatement("update projects set name = ? where rowid = ?");
      prep.setQueryTimeout(30);
      prep.setString(1, name);
      prep.setLong(2, projectId);
      prep.executeUpdate();
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, null, e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
          CrashReport.createAndLogError(LOG, null, collectUserProjectErrorInfo(userId, projectId), e);
        }
      }
    }
  }

  @Override
  public long getProjectDateBuilt(final String userId, final long projectId) {
    return getProjectDates(userId, projectId, "built");
  }

  @Override
  public long getProjectDateModified(final String userId, final long projectId) {
    return getProjectDates(userId, projectId, "modified");
  }

  @Override
  public String getProjectHistory(final String userId, final long projectId) {
    return getProjectStrings(userId, projectId, "history");
  }

  @Override
  public void addFilesToUser(final String userId, final String... fileNames) {
    // This is a no-op in the local data storage implementation
  }

  @Override
  public List<String> getUserFiles(final String userId) {
    final List<String> fileList = new ArrayList<String>();
    File userDir = new File(storageRoot.get() + "/" + userId);
    for (String fileName : userDir.list()) {
      if (fileName.equals(StorageUtil.ANDROID_KEYSTORE_FILENAME) ||
        fileName.equals(StorageUtil.USER_BACKPACK_FILENAME)) {
        fileList.add(fileName);
      }
    }
    return fileList;
  }

  @Override
  public void uploadUserFile(final String userId, final String fileName,
      final String content, final String encoding) {
    try {
      uploadRawUserFile(userId, fileName, content.getBytes(encoding));
    } catch (UnsupportedEncodingException e) {
      // XXX
    }
  }

  @Override
  public void uploadRawUserFile(String userId, String fileName,
      final byte[] content) {
    FileOutputStream out = null;
    byte [] empty = new byte[] { (byte)0x5b, (byte)0x5d }; // "[]" in bytes
    if (!fileName.equals(StorageUtil.ANDROID_KEYSTORE_FILENAME) && !fileName.equals(StorageUtil.USER_BACKPACK_FILENAME)
        && !fileName.equals(APPSTORE_CREDENTIALS_FILENAME)) {
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId, fileName),
          new RuntimeException("Only android keystores are supported filename = " + fileName));
    }
    try {
      File fileObject = new File(storageRoot.get() + "/" + userId + "/" + fileName);
      if (fileName.equals(StorageUtil.USER_BACKPACK_FILENAME)) {
        if (Arrays.equals(empty, content)) {
          // We are storing the backpack and the contents are the empty JSON array
          // then we just delete the file, if it exists
          if (fileObject.exists()) {
            fileObject.delete();
          }
          return;
        }
      }
      out = new FileOutputStream(fileObject);
      out.write(content);
      out.close();
      out = null;
    } catch (IOException e) {
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId, fileName), e);
    } finally {
      if (out != null) {
        try {
          out.close();
        } catch (Exception e) {
        }
      }
    }
  }

  @Override
  public String downloadUserFile(final String userId, final String fileName,
      final String encoding) {
    // Likely not used
    try {
      return (new String(downloadRawUserFile(userId, fileName), encoding));
    } catch (UnsupportedEncodingException e) {
      throw CrashReport.createAndLogError(LOG, null, "Unsupported file content encoding, " +
          collectUserErrorInfo(userId, fileName), e);
    }
  }

  @Override
  public byte[] downloadRawUserFile(final String userId, final String fileName) {
    // Only support android.keystore and backpack.xml
    LOG.debug("downloadRawUserFile: fileName = " + fileName);
    if (!fileName.equals(StorageUtil.ANDROID_KEYSTORE_FILENAME) &&
        !fileName.equals(StorageUtil.USER_BACKPACK_FILENAME) && !fileName.equals(APPSTORE_CREDENTIALS_FILENAME)) {
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId, fileName),
          new RuntimeException("Only android keystores and backpack are supported filename = " + fileName));
    }
    File fileObject = new File(storageRoot.get() + "/" + userId + "/" + fileName);
    FileInputStream in = null;
    byte [] result;
    try {
      if (!fileObject.exists()) {
        if (fileName.equals(StorageUtil.USER_BACKPACK_FILENAME)) {
        }
        return null;
      }
      int fileLength = (int)fileObject.length();
      result = new byte[fileLength];
      in = new FileInputStream(fileObject);
      int dataToRead = fileLength;
      int dataRead = 0;
      int chunkLen = 0;
      while ((chunkLen = in.read(result, dataRead, dataToRead)) > 0) {
        dataToRead = dataToRead - chunkLen;
        dataRead += chunkLen;
        if (dataToRead <= 0)
          break;
      }
      return result;
    } catch (IOException e) {
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId, fileName), e);
    } finally {
      if (in != null) {
        try {
          in.close();
        } catch (Exception e) {
        }
      }
    }
  }

  @Override
  public void deleteUserFile(final String userId, final String fileName) {
    // Only support android.keystore
    if (!fileName.equals("android.keystore"))
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId, fileName),
          new RuntimeException("Only android keystores are supported fileName = " + fileName));
    File keystore = new File(storageRoot.get() + "/" + userId + "/android.keystore");
    try {
      keystore.delete();
    } catch (Exception e) {
    }
  }

  @Override
  public int getMaxJobSizeBytes() {
    // TODO(user): what should this mean?
    return 5 * 1024 * 1024;
  }

  @Override
  public void addSourceFilesToProject(final String userId, final long projectId,
      final boolean changeModDate, final String... fileNames) {
    // This is a noop in the local storage implementation
  }

  @Override
  public void addOutputFilesToProject(final String userId, final long projectId,
      final String... fileNames) {
    // This is a noop in the local storage implementation
  }

  private void removeFilesFromProject(String userId, long projectId, String... fileNames) {
    for (String fileName : fileNames) {
      try {
        File zFile = new File(storageRoot.get() + "/" + userId + "/" + projectId + "/" + fileName);
        zFile.delete();
      } catch (Exception e) {
        // XXX
      }
    }
  }

  @Override
  public void removeSourceFilesFromProject(final String userId, final long projectId,
      final boolean changeModDate, final String... fileNames) {
    removeFilesFromProject(userId, projectId, fileNames);
  }

  @Override
  public void removeOutputFilesFromProject(final String userId, final long projectId,
      final String... fileNames) {
    removeFilesFromProject(userId, projectId, fileNames);
  }

  // Walk the project's file tree looking for files
  private void getProjectFiles(String userId, long projectId, String prefix, boolean isSource, List<String> result)
    throws IOException {
    File top = new File(storageRoot.get() + "/" + userId + "/" + projectId + "/" + prefix);
    for (File file : top.listFiles()) {
      if (file.isFile()) {
        if (isSource) {
          if (!file.getName().endsWith(".apk") && !file.getName().endsWith(".out"))
            result.add(prefix + "/" + file.getName());
        } else {
          if (file.getName().endsWith(".apk") || file.getName().endsWith(".out"))
            result.add(prefix + "/" + file.getName());
        }
      } else {
        if (prefix.equals("")) {
          getProjectFiles(userId, projectId, file.getName(), isSource, result);
        } else {
          getProjectFiles(userId, projectId, prefix + "/" + file.getName(), isSource, result);
        }
      }
    }
  }

  @Override
  public List<String> getProjectSourceFiles(final String userId, final long projectId) {
    LOG.debug("getProjectSourceFiles: userId = " + userId + " projectId = " + projectId);
    List<String> result = new ArrayList<String>();
    try {
      getProjectFiles(userId, projectId, "", true, result);
      for (String zFile : result) {
        LOG.debug("getProjectSourceFiles: File = " + zFile);
      }
      return result;
    } catch (IOException e) {
      throw CrashReport.createAndLogError(LOG, null,
          collectUserProjectErrorInfo(userId, projectId), e);
    }
  }

  @Override
  public List<String> getProjectOutputFiles(final String userId, final long projectId) {
    List<String> result = new ArrayList<String>();
    try {
      getProjectFiles(userId, projectId, "", false, result);
      return result;
    } catch (IOException e) {
      throw CrashReport.createAndLogError(LOG, null,
          collectUserProjectErrorInfo(userId, projectId), e);
    }
  }

  @Override
  public long uploadFile(final long projectId, final String fileName, final String userId,
      final String content, final String encoding) throws BlocksTruncatedException {
    try {
      return uploadRawFile(projectId, fileName, userId, false, content.getBytes(encoding));
    } catch (UnsupportedEncodingException e) {
      throw CrashReport.createAndLogError(LOG, null, "Unsupported file content encoding,"
          + collectProjectErrorInfo(null, projectId, fileName), e);
    }
  }

  @Override
  public long uploadFileForce(final long projectId, final String fileName, final String userId,
      final String content, final String encoding) {
    try {
      return uploadRawFileForce(projectId, fileName, userId, content.getBytes(encoding));
    } catch (UnsupportedEncodingException e) {
      throw CrashReport.createAndLogError(LOG, null, "Unsupported file content encoding,"
          + collectProjectErrorInfo(null, projectId, fileName), e);
    }
  }

  private void updateProjectModDate(String userId, long projectId) {
    java.sql.Date modDate = new java.sql.Date(System.currentTimeMillis());
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + storageRoot.get() + "/" + userId + "/projects.sqlite");
      PreparedStatement prep = conn.prepareStatement("update projects set modified = ? where rowid = ?");
      prep.setQueryTimeout(30);
      prep.setDate(1, modDate);
      prep.setLong(2, projectId);
      prep.executeUpdate();
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, null, e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
          CrashReport.createAndLogError(LOG, null, collectUserProjectErrorInfo(userId, projectId), e);
        }
      }
    }
  }

  @Override
  public long updateProjectBuiltDate(final String userId, final long projectId, final long builtDate) {
    java.sql.Date built = new java.sql.Date(builtDate);
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + storageRoot.get() + "/" + userId + "/projects.sqlite");
      PreparedStatement prep = conn.prepareStatement("update projects set built = ? where rowid = ?");
      prep.setQueryTimeout(30);
      prep.setDate(1, built);
      prep.setLong(2, projectId);
      prep.executeUpdate();
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, null, e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
          CrashReport.createAndLogError(LOG, null, collectUserProjectErrorInfo(userId, projectId), e);
        }
      }
    }
    return builtDate;
  }

  @Override
  public long uploadRawFileForce(final long projectId, final String fileName, final String userId,
      final byte[] content) {
    try {
      return uploadRawFile(projectId, fileName, userId, true, content);
    } catch (BlocksTruncatedException e) {
      // Won't get here, exception isn't thrown when force is true
      return 0;
    }
  }

  @Override
  public long uploadRawFile(final long projectId, final String fileName, final String userId,
      final boolean force, final byte[] content) throws BlocksTruncatedException {
    final boolean considerBackup = ((fileName.contains("src/") && fileName.endsWith(".blk")) // AI1 Blocks Files
        || (fileName.contains("src/") && fileName.endsWith(".bky")) // Blockly files
                                    || (fileName.contains("src/") && fileName.endsWith(".scm"))); // Form Definitions
    try {
      if ((content.length < 120) && (fileName.endsWith(".bky")) && !force)
        throw new BlocksTruncatedException();
      File theFile = new File(storageRoot.get() + "/" + userId + "/" + projectId + "/" + fileName);
      if (theFile.exists() && considerBackup) {   // check to see if we should back it up
        if ((theFile.lastModified() + backupTime) < System.currentTimeMillis()) {
          // Yes backup, which in this case means we rename the file
          String renamedFileName = storageRoot.get() + File.separator +
            userId + File.separator + projectId + File.separator +
            fileName + "." + formattedTime() + ".backup";
          if (System.getProperty("os.name").startsWith("Windows")) {
            renamedFileName = renamedFileName.replace(":", "-"); // Windows doesn't like
                                                         // :'s in file names
          }
          File renamedFile = new File(renamedFileName);
          if (!theFile.renameTo(renamedFile)) {
            throw CrashReport.createAndLogError(LOG, null,
                collectProjectErrorInfo(userId, projectId, fileName),
                new RuntimeException("File Rename for Backup Failed new filename = " + renamedFile));
          }
        }
      }
      createRawFile(userId, projectId, fileName, content); // Actually write the file
      updateProjectModDate(userId, projectId);
      // Return the current time as the modification time
      return System.currentTimeMillis();
    } catch (IOException e) {
      throw CrashReport.createAndLogError(LOG, null,
          collectProjectErrorInfo(userId, projectId, fileName), e);
    }
  }

  @Override
  public long deleteFile(final String userId, final long projectId, final String fileName) {
    File theFile = new File(storageRoot.get() + "/" + userId + "/" + projectId + "/" + fileName);
    if (theFile.delete())
      updateProjectModDate(userId, projectId);
    return System.currentTimeMillis();
  }

  // TODO(user) - just use "UTF-8" (instead of having an encoding argument),
  // which will never cause UnsupportedEncodingException. (Here and in other
  // methods with the encoding arg.
  @Override
  public String downloadFile(final String userId, final long projectId, final String fileName,
      final String encoding) {
    try {
      String retval = new String(downloadRawFile(userId, projectId, fileName), encoding);
      return retval;
    } catch (UnsupportedEncodingException e) {
      throw CrashReport.createAndLogError(LOG, null, "Unsupported file content encoding, "
          + collectProjectErrorInfo(userId, projectId, fileName), e);
    }
  }

  @Override
  public void recordCorruption(String userId, long projectId, String fileId, String message) {
    // Not Implemented (for now).
  }

  @Override
  public byte[] downloadRawFile(final String userId, final long projectId, final String fileName) {
    LOG.debug("downloadRawFile: fileName = " + fileName);
    FileInputStream in = null;
    byte [] result;
    try {
      File theFile = new File(storageRoot.get() + "/" + userId + "/" + projectId + "/" + fileName);
      if (!theFile.exists()) {
        return null;
      }
      int fileLength = (int)theFile.length();
      result = new byte[fileLength];
      in = new FileInputStream(theFile);
      int dataToRead = fileLength;
      int dataRead = 0;
      int chunkLen = 0;
      while ((chunkLen = in.read(result, dataRead, dataToRead)) > 0) {
        dataToRead = dataToRead - chunkLen;
        dataRead += chunkLen;
        if (dataToRead <= 0)
          break;
      }
      return result;
    } catch (IOException e) {
      throw CrashReport.createAndLogError(LOG, null, "Unsupported file content encoding, "
          + collectProjectErrorInfo(userId, projectId, fileName), e);
    } finally {
      if (in != null) {
        try {
          in.close();
        } catch (Exception e) {
        }
      }
    }
  }

  /**
   *  Exports project files as a zip archive
   * @param userId a user Id (the request is made on behalf of this user)
   * @param projectId  project ID
   * @param includeProjectHistory  whether or not to include the project history
   * @param includeAndroidKeystore  whether or not to include the Android keystore
   * @param zipName  the name of the zip file, if a specific one is desired

   * @return  project with the content as requested by params.
   */
  @Override
  public ProjectSourceZip exportProjectSourceZip(final String userId, final long projectId,
      final boolean includeProjectHistory,
      final boolean includeAndroidKeystore,
      @Nullable String zipName, boolean includeYail,
      boolean includeScreenShots,
      boolean forGallery,
      boolean fatalError,
      final boolean forAppStore,
      final boolean locallyCachedApp) throws IOException {
    int fileCount = 0;
    ByteArrayOutputStream zipFile = new ByteArrayOutputStream();
    ZipOutputStream out = new ZipOutputStream(zipFile);
    List<String> sources = getProjectSourceFiles(userId, projectId);
    for (String fileName : sources) {
      if (fileName.equals(FileExporter.REMIX_INFORMATION_FILE_PATH) ||
          (fileName.startsWith("screenshots") && !includeScreenShots) ||
          (fileName.startsWith("src/") && fileName.endsWith(".yail") && !includeYail) ||
          (fileName.startsWith("src/") && fileName.endsWith(".bky") && locallyCachedApp) ||
          (fileName.startsWith("src/") && fileName.endsWith(".scm") && locallyCachedApp)) {
        // Don't include YAIL files when exporting projects
        // includeYail will be set to true when we are exporting the source
        // to send to the buildserver or when the person exporting
        // a project is an Admin (for debugging).
        // Otherwise Yail files are confusing cruft. In the case of
        // the Firebase Component they may contain secrets which we would
        // rather not have leak into an export .aia file or into the Gallery
        // NOTE: Standalone code doesn't include a Gallery, but will likely
        // include one in the future.
        continue;
      }
      byte [] data = downloadRawFile(userId, projectId, fileName);
      if (fileName.endsWith(".properties") && locallyCachedApp == true) {
        String projectProperties = new String(data, StandardCharsets.UTF_8);
        Properties oldProperties = new Properties();
        try {
          oldProperties.load(new StringReader(projectProperties));
        } catch (IOException e) {
          e.printStackTrace();
        }
        YoungAndroidSettingsBuilder oldPropertiesBuilder = new YoungAndroidSettingsBuilder(oldProperties);
        String updatedProperties = oldPropertiesBuilder.setAIVersioning(Integer.toString(YOUNG_ANDROID_VERSION)).toProperties();
        data = updatedProperties.getBytes(StandardCharsets.UTF_8);
      }
      out.putNextEntry(new ZipEntry(fileName));
      out.write(data, 0, data.length);
      fileCount++;
    }
    if (includeProjectHistory) {
      String history = getProjectHistory(userId, projectId);
      if (history != null) {
        byte [] data = history.getBytes(StorageUtil.DEFAULT_CHARSET);
        out.putNextEntry(new ZipEntry(FileExporter.REMIX_INFORMATION_FILE_PATH));
        out.write(data, 0, data.length);
        out.closeEntry();
        fileCount++;
      }
    }
    if (includeAndroidKeystore) {
      byte [] data = downloadRawUserFile(userId, StorageUtil.ANDROID_KEYSTORE_FILENAME);
      if (data != null) {
        out.putNextEntry(new ZipEntry(StorageUtil.ANDROID_KEYSTORE_FILENAME));
        out.write(data, 0, data.length);
        out.closeEntry();
        fileCount++;
      }
      if (forAppStore) {
        data = downloadRawUserFile(userId, StorageUtil.APPSTORE_CREDENTIALS_FILENAME);
        if (data != null) {
          out.putNextEntry(new ZipEntry(StorageUtil.APPSTORE_CREDENTIALS_FILENAME));
          out.write(data, 0, data.length);
          out.closeEntry();
          fileCount++;
        }
      }
    }
    if (fileCount == 0) {
      // can't close out since will get a ZipException due to the lack of files
      throw new IllegalArgumentException("No files to download");
    }
    out.close();

    String projectName = getProjectName(userId, projectId);
    if (zipName == null) {
      zipName = projectName + ".aia";
    }

    ProjectSourceZip projectSourceZip =
        new ProjectSourceZip(zipName, zipFile.toByteArray(), fileCount);
    projectSourceZip.setMetadata(projectName);
    return projectSourceZip;
  }

  @Override
  public String findUserByEmail(String inputemail) throws NoSuchElementException {
    User user = getUser(null, inputemail, false);
    if (user == null) {
        throw new NoSuchElementException("Couldn't find a user with email " + inputemail);
    }
    return user.getUserId();
  }

  @Override
  public String findIpAddressByKey(final String key) {
    Connection conn = null;
    try {
      long ts = System.currentTimeMillis();
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      PreparedStatement prep = conn.prepareStatement("select ipaddr from rendezvous where key = ?");
      prep.setString(1, key);
      ResultSet rs = prep.executeQuery();
      if (rs.next()) {
        String ipaddr = rs.getString("ipaddr");
        prep.close();
        return ipaddr;
      } else {
        prep.close();
        return null;
      }
    } catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, null, e);
    }
  }

  @Override
  public void storeIpAddressByKey(final String key, final String ipAddress) {
    Connection conn = null;
    try {
      long ts = System.currentTimeMillis();
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      PreparedStatement prep = conn.prepareStatement("insert or replace into rendezvous (key, ipaddr, timestamp) " +
        "values (?, ?, ?)");
      prep.setString(1, key);
      prep.setString(2, ipAddress);
      prep.setDate(3, new java.sql.Date(ts));
      prep.executeUpdate();
      prep.close();
      prep = conn.prepareStatement("delete from rendezvous where timestamp < ?");
      prep.setDate(1, new java.sql.Date(ts-(1000*3600))); // Older then an hour
      prep.executeUpdate();
      prep.close();
    } catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, null, e);
    }
  }

  @Override
  public boolean checkWhiteList(String email) {
    // Not Implemented Yet
    return true;
  }

  @Override
  public void storeFeedback(final String notes, final String foundIn, final String faultData,
    final String comments, final String datestamp, final String email, final String projectId) {
    // Not Implemented Yet
  }

  // Nonce Management Routines.
  // The Nonce is used to map to userId and ProjectId and is used
  // for non-authenticated access to a built APK file.

  @Override
  public void storeNonce(final String nonceValue, final String userId, final long projectId) {
    Connection conn = null;
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      PreparedStatement prep = conn.prepareStatement("insert into nonce (nonce, userid, projectid, timestamp)" +
          " values (?, ?, ?, ?)");
      prep.setQueryTimeout(30);
      prep.setString(1, nonceValue);
      prep.setString(2, userId);
      prep.setLong(3, projectId);
      prep.setDate(4, new java.sql.Date(System.currentTimeMillis()));
      prep.executeUpdate();
      prep.close();
    } catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null,
          collectUserProjectErrorInfo(userId, projectId), e);
    }
  }

  @Override
  public Nonce getNoncebyValue(String nonceValue) {
    Connection conn = null;
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      PreparedStatement prep = conn.prepareStatement("select * from nonce where nonce = ?");
      prep.setString(1, nonceValue);
      ResultSet rs = prep.executeQuery();
      if (rs.next()) {
        Nonce retval =new Nonce(rs.getString("nonce"),
            rs.getString("userid"),
            rs.getLong("projectid"),
            new java.util.Date(rs.getDate("timestamp").getTime()));
        prep.close();
        return retval;
      } else {
        prep.close();
        return null;
      }
    }
    catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, null, e);
    }
  }

  @Override
  public SplashConfig getSplashConfig() {
    Connection conn = null;
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      PreparedStatement prep = conn.prepareStatement("select version, width, height, content from splashconfig where rowid = 1");
      ResultSet rs = prep.executeQuery();
      if (rs.next()) {
        SplashConfig retval = new SplashConfig(rs.getInt("version"),
          rs.getInt("width"), rs.getInt("height"),
          rs.getString("content"));
        prep.close();
        return retval;
      } else {
        prep.close();
        return new SplashConfig(0, 640, 100, "Welcome to MIT App Inventor");
      }
    }
    catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, null, e);
    }
  }

  // Cleanup expired nonces which are older then 3 hours. Normal Nonce lifetime
  // is 2 hours. So for one hour they persist and return "link expired" instead of
  // "link not found" (after the object itself is removed).

  @Override
  public void cleanupNonces() {
    Connection conn = null;
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      PreparedStatement prep = conn.prepareStatement("delete from nonce where timestamp < ?");
      prep.setQueryTimeout(30);
      prep.setDate(1, new java.sql.Date(System.currentTimeMillis() - 3*3600*1000));
      prep.executeUpdate();
      prep.close();
    } catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, null, e);
    }
  }

  @Override
  public PWData createPWData(final String email) {
    Connection conn = null;
    try {
      long ts = System.currentTimeMillis();
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      String uuid = UUID.randomUUID().toString();
      PreparedStatement prep = conn.prepareStatement("insert into pwdata (uuid, email, timestamp) " +
        "values (?, ?, ?)");
      prep.setQueryTimeout(30);
      prep.setString(1, uuid);
      prep.setString(2, email);
      prep.setDate(3, new java.sql.Date(ts));
      prep.executeUpdate();
      prep.close();
      PWData pwData = new PWData();
      pwData.id = uuid;
      pwData.email = email;
      pwData.timestamp = new Date(ts);
      return pwData;
    } catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, null, e);
    }
  }

  @Override
  public PWData findPWData(final String uid) {
    LOG.debug("findPWData called, uid = " + uid);
    Connection conn = null;
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      PreparedStatement prep = conn.prepareStatement("select * from pwdata where uuid = ?");
      prep.setString(1, uid);
      ResultSet rs = prep.executeQuery();
      if (rs.next()) {
        PWData pwData = new PWData();
        pwData.id = uid;
        pwData.email = rs.getString("email");
        pwData.timestamp = new java.util.Date(rs.getDate("timestamp").getTime());
        LOG.debug("findPWData returning pwData.email = " + pwData.email);
        prep.close();
        return pwData;
      } else {
        LOG.debug("findPWData returning null.");
        prep.close();
        return null;
      }
    } catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, null, e);
    }
  }

  // Remove expired PWData elements from the datastore
  @Override
  public void cleanuppwdata() {
    Connection conn = null;
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      long ts = System.currentTimeMillis() - 3600*1000; // An Hour Ago
      PreparedStatement prep = conn.prepareStatement("delete from pwdata where timestamp < ?");
      prep.setQueryTimeout(30);
      prep.setDate(1, new java.sql.Date(ts));
      prep.executeUpdate();
      prep.close();
    } catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, null, e);
    }
  }

  // Fetch license data
  @Override
  public LicenseConfig getLicenseConfig() {
    Connection conn = null;
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      PreparedStatement prep = conn.prepareStatement("select uuid, hardware, authcode from license limit 1");
      ResultSet rs = prep.executeQuery();
      if (rs.next()) {
        LicenseConfig conf = new LicenseConfig(rs.getString("hardware"),
          rs.getString("uuid"), rs.getString("authcode"));
        prep.close();
        return conf;
      } else {
        prep.close();
        return null;
      }
    } catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, null, e);
    }
  }

  @Override
  public void setLicenseConfig(LicenseConfig conf) {
    Connection conn = null;
    PreparedStatement prep;
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      LicenseConfig oldConf = getLicenseConfig();
      String hardwareHint = conf.getHardwareHint();
      String UUID = conf.getUUID();
      String authCode = conf.getAuthCode();
      if (oldConf != null) {
        if (hardwareHint == null)
          hardwareHint = oldConf.getHardwareHint();
        if (UUID == null)
          UUID = oldConf.getUUID();
        if (authCode == null)
          authCode = oldConf.getAuthCode();
        prep = conn.prepareStatement("update or replace license set hardware = ?, uuid = ?, authcode = ? where rowid = 1");
        prep.setQueryTimeout(30);
        prep.setString(1, hardwareHint);
        prep.setString(2, UUID);
        prep.setString(3, authCode);
        prep.executeUpdate();
        prep.close();
      } else {
        prep = conn.prepareStatement("insert into license (hardware, uuid, authcode) values (?, ?, ?)");
        prep.setQueryTimeout(30);
        prep.setString(1, hardwareHint);
        prep.setString(2, UUID);
        prep.setString(3, authCode);
        prep.executeUpdate();
        prep.close();
      }
    } catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, null, e);
    }
  }

  @Override
  public List<AdminUser> searchUsers(String partialEmail) {
    Connection conn = null;
    ResultSet rs;
    List<AdminUser> retval = new ArrayList();
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      PreparedStatement prep;
      prep = conn.prepareStatement("select * from users where emaillower > ? limit 20");
      prep.setString(1, partialEmail.toLowerCase());
      rs = prep.executeQuery();

      while (rs.next()) {
        java.sql.Timestamp ts = rs.getTimestamp("visited");
        java.util.Date visited = new java.util.Date(ts.getTime());
        AdminUser user = new AdminUser(rs.getString("uuid"), rs.getString("email"),
          rs.getString("email"), rs.getBoolean("tosaccepted"),
          rs.getBoolean("isadmin"), visited);
        retval.add(user);
      }
      return retval;
    } catch (SQLException e) {
      userConn.remove();
      try {
        conn.close();
      } catch (Exception ee) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, null, e);
    }
  }

  @Override
  public void storeUser(AdminUser user) throws AdminInterfaceException {
    Connection conn = null;
    User userData = null;
    if (user.getId() != null) {
      userData = getUser(user.getId());
    }
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      PreparedStatement prep;
      if (userData != null) {
        // Update them
        String password = user.getPassword();
        boolean isAdmin = user.getIsAdmin();
        if (password != null && !password.equals("")) { // We have a password
          prep = conn.prepareStatement("update users set password = ?, isadmin = ? where uuid = ?");
          prep.setQueryTimeout(30);
          prep.setString(1, password);
          prep.setBoolean(2, isAdmin);
          prep.setString(3, user.getId());
          prep.executeUpdate();
          prep.close();
        } else {                // Only set isadmin
          prep = conn.prepareStatement("update users set isadmin = ? where uuid = ?");
          prep.setBoolean(1, isAdmin);
          prep.setString(2, user.getId());
          prep.executeUpdate();
          prep.close();
        }
      } else {
        // Add them
        // First let's make sure the email address is unique
        prep = conn.prepareStatement("select * from users where emaillower = ?");
        prep.setString(1, user.getEmail().toLowerCase());
        ResultSet rs = prep.executeQuery();
        if (rs.next()) {
          prep.close();
          throw new AdminInterfaceException("User Already Exists with email = " + user.getEmail());
        }
        // Got this far, we can really add them
        prep.close();
        userData= createUser(user.getEmail(), null, conn);
        prep = conn.prepareStatement("update users set isadmin = ?, password = ? where uuid = ?");
        prep.setBoolean(1, user.getIsAdmin());
        prep.setString(2, user.getPassword());
        prep.setString(3, userData.getUserId());
        prep.executeUpdate();
        prep.close();
      }
    } catch (SQLException e) {
      // Something went wrong, we'll flush this connection as a result...
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, null, e);
    }
  }

  @Override
  public String uploadTempFile(byte [] content) throws IOException {
    File tempPath = new File(storageRoot.get() + "/__TEMP__");
    if (!tempPath.exists()) {
      tempPath.mkdir();
    } else if (!tempPath.isDirectory()) {
      try {
        throw new IOException("tempPath is not a directory!");
      } catch (IOException e) {
        throw CrashReport.createAndLogError(LOG, null, null, e);
      }
    }
    String fileName = "__TEMP__/" + UUID.randomUUID().toString();
    tempPath = new File(storageRoot.get() + "/" + fileName);
    LOG.debug("Creating Temp file " + fileName);
    boolean done = false;
    try {
      FileOutputStream fout = new FileOutputStream(tempPath);
      fout.write(content);
      fout.close();
      done = true;
    } finally {
      if (!done) {              // Something went wrong, cleanup
        tempPath.delete();
      }
    }
    return fileName;
  }

  @Override
  public InputStream openTempFile(String fileName) throws IOException {
    File tempPath = new File(storageRoot.get() + "/" + fileName);
    LOG.debug("Opening " + tempPath);
    return new FileInputStream(tempPath);
  }

  @Override
  public void deleteTempFile(String fileName) throws IOException {
    if (fileName.indexOf(".") != -1) {
      try {
        throw new IOException("Invalid character in temp file name.");
      } catch (IOException e) {
        throw CrashReport.createAndLogError(LOG, null, null, e);
      }
    }
    File tempPath = new File(storageRoot.get() + "/" + fileName);
    tempPath.delete();
    LOG.debug("Deleting " + tempPath);
  }

  @Override
  public User createAnonymousAccount() {
    Connection conn = null;
    ResultSet rs;
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }

      String userId;
      User user;
      while (true) {
        userId = AccountUtil.generateAccountId();
        user = getUser(userId, null, false);
        if (user != null)         // Already have one with this Id
          continue;               // Loop around, try a different random Id
        // At this point we have an unused userId. Note: There is a race here
        // but it is low probability.
        createUser(userId, userId, conn);
        user = getUser(userId);
        return user;
      }
    } catch (SQLException ee) {
      throw CrashReport.createAndLogError(LOG, null, null, ee);
    }
  }

  @Override
  public String downloadBackpack(String backPackId) {
    try {
      backPackId.replace("/", "-"); // Make sure no games are played
      File fileObject = new File(storageRoot.get() + "/BACKPACKS/" + backPackId);
      BufferedReader input = new BufferedReader(new FileReader(fileObject));
      StringBuilder sb = new StringBuilder();
      String line;
      while ((line = input.readLine()) != null) {
        sb.append(line);
        sb.append("\n");
      }
      input.close();
      return sb.toString();
    } catch (Exception e) {
      throw CrashReport.createAndLogError(LOG, null, null, e);
    }
  }

  @Override
  public void uploadBackpack(String backPackId, String content) {
    try {
      backPackId.replace("/", "-"); // Make sure no games are played
      File fileObject = new File(storageRoot.get() + "/BACKPACKS/" + backPackId);
      PrintWriter output = new PrintWriter(fileObject);
      output.write(content);
      output.close();
    } catch (Exception e) {
      throw CrashReport.createAndLogError(LOG, null, null, e);
    }
  }

  @Override
  public void storeBuildStatus(String userId, long projectId, int progress) {
    Connection conn = null;
    try {
      conn = buildConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + BUILDSTATUS_DATABASE);
        buildConn.set(conn);
      }
      PreparedStatement prep;
      prep = conn.prepareStatement("insert into builds values (?, ?, ?, ?)");
      prep.setQueryTimeout(30);
      prep.setString(1, userId);
      prep.setLong(2, projectId);
      prep.setInt(3, progress);
      prep.setDate(4, new java.sql.Date(System.currentTimeMillis()));
      prep.executeUpdate();
      prep.close();
    } catch (SQLException e) {
      try {
        conn.close();
      } catch (Exception ee) {
        // XXX
      }
      buildConn.set(null);
      throw CrashReport.createAndLogError(LOG, null, null, e);
    }
  }

  @Override
  public int getBuildStatus(String userId, long projectId) {
    Connection conn = null;
    try {
      conn = buildConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + BUILDSTATUS_DATABASE);
        buildConn.set(conn);
      }
      PreparedStatement prep = conn.prepareStatement("select progress from builds where userid = ? and projectid = ?");
      prep.setQueryTimeout(30);
      prep.setString(1, userId);
      prep.setLong(2, projectId);
      ResultSet rs = prep.executeQuery();
      if (rs.next()) {
        int progress = rs.getInt("progress");
        prep.close();
        return progress;
      } else {
        return 50;                // Kludge
      }
    } catch (SQLException e) {
      try {
        conn.close();
      } catch (Exception ee) {
        // XXX
      }
      buildConn.set(null);
      throw CrashReport.createAndLogError(LOG, null, null, e);
    }
  }

  @Override
  public void assertUserHasProject(String userId, long projectId) {
    // We are a no-op in this storage backend as this cannot happen here
  }

  private static String collectUserErrorInfo(final String userId) {
    return collectUserErrorInfo(userId, CrashReport.NOT_AVAILABLE);
  }

  private static String collectUserErrorInfo(final String userId, String fileName) {
    return "user=" + userId + ", file=" + fileName;
  }

  private static String collectProjectErrorInfo(final String userId, final long projectId,
      final String fileName) {
    return "user=" + userId + ", project=" + projectId + ", file=" + fileName;
  }

  private static String collectUserProjectErrorInfo(final String userId, final long projectId) {
    return "user=" + userId + ", project=" + projectId;
  }

  // Return time in ISO_8660 format
  private static String formattedTime() {
    java.text.SimpleDateFormat formatter = new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
    return formatter.format(new java.util.Date());
  }

  private boolean updateProjectsSchema(Connection conn) {
    try {
      Statement statement = conn.createStatement();
      ResultSet rs = statement.executeQuery("select sql from sqlite_master where name = 'projects'");
      if (rs.next()) {
        String sql = rs.getString("sql");
        LOG.debug("sql = " + sql);
        sql = sql.toLowerCase();
        if (sql.equals("create table projects (name string, settings string, created date, modified date, history string, deleted boolean)")) {
          rs.close();
          statement.executeUpdate("alter table projects add column trashed boolean");
          statement.executeUpdate("alter table projects add column built date");
          statement.executeUpdate("update projects set trashed = 0, built = 0");
          statement.close();
          return true;
        } else if (sql.equals("create table projects (name string, settings string, created date, modified date, history string, deleted boolean, trashed boolean)")) {
          rs.close();
          statement.executeUpdate("alter table projects add column built date");
          statement.executeUpdate("update projects set built = 0");
          statement.close();
          return true;
        } else {
          LOG.warn("Unknown schema during projects schema update: " + sql);
          return false;
        }
      } else {
        return false;             // ?
      }
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null,
        null, e);
    }
  }

  @Override
  public List<String> getTutorialsUrlAllowed() {
    // Rather then store these in the database or the filesystem (or CEPH) we just
    // hard code them here for now
    return new ArrayList<> (Arrays.asList(
        "http://appinventor.mit.edu/",
        "https://appinventor.mit.edu/",
        "http://appinv.us/",
        "http://templates.appinventor.mit.edu/"));
  }

  @Override
  public String getIosExtensionsConfig() {
    // Rather then store these in the database or filesystem (or CEPH) we just
    // hard code them here for now
    return "[]";                // No allowed extensions
  }

  @Override
  public boolean deleteAccount(final String userId) {
    List<Long> projectIds = getProjects(userId);
    // We iterate over the projects in two loops The first loop is
    // just to determine that all remaining projects are in the trash.
    // The second loop actually removes such projects.  We do it this
    // way so that no projects are removed if any projects
    // exist. Otherwise some trashed projects may get removed before
    // we discover a live project.
    for (long projectId : projectIds) {
      UserProject data = getUserProject(userId, projectId);
      if (!data.isInTrash()) {
        return false;           // Have a live project
      }
    }
    // Got here, no live projects, remove the remainders
    // We do not actually have to remove the projects here
    // because in the next step we are going to remove the
    // user's entire directory, which includes all projects
    File userDir = new File(storageRoot.get() + "/" + userId);
    LOG.info("deleteAccount: path = " + userDir.getAbsolutePath());
    if(!deleteDirectory(userDir)) {           // No going back now!
      LOG.info("deleteAccount: deletion failed");
    }
    Connection conn = null;
    try {
      conn = userConn.get();
      if (conn == null) {
        conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
        userConn.set(conn);
      }
      PreparedStatement prep = conn.prepareStatement("delete from users where uuid = ?");
      prep.setQueryTimeout(30);
      prep.setString(1, userId);
      prep.executeUpdate();
      prep.close();
    } catch (SQLException e) {
      userConn.remove();
      try {
        conn.close();
      } catch (Exception z) {
      }
      conn = null;
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
    }
    return true;
  }

  private static boolean deleteDirectory(File directoryToBeDeleted) {
    File[] allContents = directoryToBeDeleted.listFiles();
    if (allContents != null) {
      for (File file : allContents) {
        deleteDirectory(file);
      }
    }
    return directoryToBeDeleted.delete();
  }
}

