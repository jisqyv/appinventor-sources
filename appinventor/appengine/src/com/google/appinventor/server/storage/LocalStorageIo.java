// -*- mode: java; c-basic-offset: 2; -*-
// Copyright 2009-2011 Google, All Rights reserved
// Copyright 2011-2012 MIT, All rights reserved
// Released under the MIT License https://raw.github.com/mit-cml/app-inventor/master/mitlicense.txt

package com.google.appinventor.server.storage;

import com.google.appinventor.server.CrashReport;
import com.google.appinventor.server.FileExporter;
import com.google.appinventor.server.flags.Flag;
import com.google.appinventor.server.storage.StoredData.CorruptionRecord;
import com.google.appinventor.server.storage.StoredData.FeedbackData;
import com.google.appinventor.server.storage.StoredData.FileData;
import com.google.appinventor.server.storage.StoredData.MotdData;
import com.google.appinventor.server.storage.StoredData.NonceData;
import com.google.appinventor.server.storage.StoredData.ProjectData;
import com.google.appinventor.server.storage.StoredData.PWData;
import com.google.appinventor.server.storage.StoredData.UserData;
import com.google.appinventor.server.storage.StoredData.UserFileData;
import com.google.appinventor.server.storage.StoredData.UserProjectData;
import com.google.appinventor.server.storage.StoredData.RendezvousData;
import com.google.appinventor.server.storage.StoredData.WhiteListData;
import com.google.appinventor.shared.rpc.BlocksTruncatedException;
import com.google.appinventor.shared.rpc.Motd;
import com.google.appinventor.shared.rpc.Nonce;
import com.google.appinventor.shared.rpc.project.Project;
import com.google.appinventor.shared.rpc.project.ProjectSourceZip;
import com.google.appinventor.shared.rpc.project.RawFile;
import com.google.appinventor.shared.rpc.project.TextFile;
import com.google.appinventor.shared.rpc.project.UserProject;
import com.google.appinventor.shared.rpc.project.youngandroid.YoungAndroidProjectNode;
import com.google.appinventor.shared.rpc.user.User;
import com.google.appinventor.shared.storage.StorageUtil;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.io.ByteStreams;

import java.io.ByteArrayOutputStream;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.nio.channels.Channels;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import java.util.Date;
import java.util.UUID;

import javax.annotation.Nullable;

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

  private static final Logger LOG = Logger.getLogger(LocalStorageIo.class.getName());

  private static final String DEFAULT_ENCODING = "UTF-8";

  private static final long MOTD_ID = 1;

  private static final long TWENTYFOURHOURS = 24*3600*1000; // 24 hours in milliseconds

  private Class driverClass;    // Keep the Driver class from being GC'd

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
      conn.setAutoCommit(false);
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
        statement.executeUpdate("drop table if exists users");
        statement.executeUpdate("create table users (uuid string, email string, emaillower string, " +
          "visited timestamp, settings string, tosaccepted boolean, isadmin boolean, sessionid string," +
          " password string, templatepath string)");
        statement.executeUpdate("create index usersuuid on users(uuid)");
        statement.executeUpdate("create index usersemail on users(email)");
        statement.executeUpdate("create index usersemaillower on users(emaillower)");
        statement.executeUpdate("create table nonce (nonce string, userid string, projectid int, timestamp timestamp)");
        statement.executeUpdate("create index noncenonce on nonce(nonce)");
        statement.executeUpdate("create index noncedate on nonce(timestamp)");
        statement.executeUpdate("create table pwdata (uuid string, email string timestamp timestamp)");
//        statement.executeUpdate("create index pwdatauuid on pwdata(uuid)");
//        statement.executeUpdate("create index pwdataemail on pwdata(email)");
        statement.close();
        conn.commit();
      } catch (SQLException ee) {
        // Something is really broken
        // XXX
      }
    } finally {
      if (conn != null) {
        try {
          conn.rollback();
          conn.close();
        } catch (Exception e) {
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
      conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
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
        boolean tosAccepted = rs.getBoolean("tosaccepted");
        boolean isAdmin = rs.getBoolean("isadmin");
        String sessionId = rs.getString("sessionid");
        return new User(uuid, zemail, tosAccepted, isAdmin, sessionId);
      } else {
        if (userId == null) {   // Only create user if lookup was by email address
          if (create)
            return createUser(email, conn);
          else
            return null;
        } else {
          return null;
        }
      }
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
    } finally {
      if (conn != null) {
        try {
          conn.rollback();
          conn.close();
        } catch (Exception e) {
        }
      }
    }
  }

  /*
   * Note: We are passed in the SQL Connection to the User Database.
   */
  private User createUser(String email, Connection conn) throws SQLException {
    String newId = UUID.randomUUID().toString();
    conn.setAutoCommit(false);
    PreparedStatement prep = conn.prepareStatement("insert into users (uid, email, emaillower, visited," +
      " settings string, tosaccepted, isadmin, sessionid, password, templatepath) " +
      "values (?, ?, ?, ?, ?, ?,?, ?, ?, ?)");
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
    // User is created in the database. Now create the user's
    // private project directory.
    File projectPath = new File(storageRoot.get() + "/" + newId);
    projectPath.mkdir();
    Connection projectDb = null;
    try {
      projectDb = DriverManager.getConnection("jdbc:sqlite:" + storageRoot.get() + "/" + newId + "/projects.sqlite");
      Statement statement = projectDb.createStatement();
      // Note: the projectId is the rowid which is auto-created
      statement.executeUpdate("create table projects (name string, settings string, created date, modified date, history string, deleted boolean)");
      statement.close();
    } finally {
      if (projectDb != null) {
        projectDb.close();
      }
    }
    conn.commit();
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
      conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
      PreparedStatement prep = conn.prepareStatement("update users set tosaccepted = 't' where uuid = ?");
      prep.setString(1, userId);
      prep.executeUpdate();
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
        }
      }
    }
  }

  @Override
  public void setUserEmail(String userId, String email) {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
      PreparedStatement prep = conn.prepareStatement("update users set email = ?, emaillower = ? where uuid = ?");
      prep.setString(3, userId);
      prep.setString(1, email);
      prep.setString(2, email.toLowerCase());
      prep.executeUpdate();
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
        }
      }
    }
  }

  @Override
  public void setUserSessionId(final String userId, final String sessionId) {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
      PreparedStatement prep = conn.prepareStatement("update users set sesssionid = ? where uuid = ?");
      prep.setString(1, sessionId);
      prep.setString(2, userId);
      prep.executeUpdate();
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
        }
      }
    }
  }

  @Override
  public void setUserPassword(String userId, String password) {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
      PreparedStatement prep = conn.prepareStatement("update users set password = ? where uuid = ?");
      prep.setString(1, password);
      prep.setString(2, userId);
      prep.executeUpdate();
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
        }
      }
    }
  }

  @Override
  public String loadSettings(String userId) {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
      PreparedStatement prep = conn.prepareStatement("select settings from users where uuid = ?");
      prep.setString(1, userId);
      ResultSet rs = prep.executeQuery();
      if (rs.next()) {
        return rs.getString("settings");
      } else {
        return "";
      }
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
        }
      }
    }
  }

  @Override
  public void storeSettings(final String userId, final String settings) {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
      PreparedStatement prep = conn.prepareStatement("update users set settings = ? where uuid = ?");
      prep.setString(1, settings);
      prep.setString(2, userId);
      prep.executeUpdate();
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
        }
      }
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
      PreparedStatement prep = conn.prepareStatement("insert into projects (name, settings, created, modified, history, deleted) " +
        "values (?, ?, ?, ?, ?, 0)");
      prep.setString(1, project.getProjectName());
      prep.setString(2, projectSettings);
      prep.setDate(3, now);
      prep.setDate(4, now);
      prep.setString(3, project.getProjectHistory());
      prep.executeUpdate();
      Statement st = conn.createStatement();
      ResultSet rs = st.executeQuery("select max(rowid) as max from projects");
      if (rs.next()) {
        projectId = rs.getLong("max"); // max(rowid) is the rowid of the row we just inserted
      }
      conn.commit();            // Commit it now. If things blow out below we may
                                // wind up with a half created project so we will
                                // have to manually back out.
    } catch (SQLException e) {
      if (conn != null) {
        try {
          conn.rollback();
          conn.close();
        } catch (Exception z) {
        }
      }
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId), e);
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
      String pathName = storageRoot.get() + "/" + userId + "/" + projectId + "/" + fileName;
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
      PreparedStatement prep = conn.prepareStatement("update projects set delete = 1 where rowid = ?");
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
      ResultSet rs = st.executeQuery("select rowid,* from projects where delete = 0");
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
        return new UserProject(projectId, rs.getString("name"),
          YoungAndroidProjectNode.YOUNG_ANDROID_PROJECT_TYPE,
          rs.getDate("created").getTime(),
          rs.getDate("modified").getTime());
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
        }
      }
    }
  }

  @Override
  public String getProjectName(final String userId, final long projectId) {
    return getProjectStrings(userId, projectId, "name");
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
      if (fileName.equals("android.keystore")) { // We only support android.keystore for now
        fileList.add(fileName);
      }
    }
    return fileList;
  }

  @Override
  public void uploadUserFile(final String userId, final String fileName,
      final String content, final String encoding) {
    // Not Implemented
    // This code was used by the old blocks editor and isn't used in App Inventor 2
    // we should remove it and its callers as they are defunct.
  }

  @Override
  public void uploadRawUserFile(String userId, String fileName,
      final byte[] content) {
    FileOutputStream out = null;
    if (!fileName.equals("android.keystore")) {
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId, fileName),
          new RuntimeException("Only android keystores are supported"));
    }
    try {
      File keystore = new File(storageRoot.get() + "/" + userId + "/android.keystore");
      out = new FileOutputStream(keystore);
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
    // Only support android.keystore
    if (!fileName.equals("android.keystore"))
      throw CrashReport.createAndLogError(LOG, null, collectUserErrorInfo(userId, fileName),
          new RuntimeException("Only android keystores are supported"));
    File keystore = new File(storageRoot.get() + "/" + userId + "/android.keystore");
    FileInputStream in = null;
    byte [] result;
    try {
      if (!keystore.exists()) {
        return null;
      }
      int fileLength = (int)keystore.length();
      result = new byte[fileLength];
      in = new FileInputStream(keystore);
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
          new RuntimeException("Only android keystores are supported"));
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
            result.add(prefix + file.getName());
        } else {
          if (file.getName().endsWith(".apk") || file.getName().endsWith(".out"))
            result.add(prefix + file.getName());
        }
      } else {
        getProjectFiles(userId, projectId, prefix + "/" + file.getName(), isSource, result);
      }
    }
  }

  @Override
  public List<String> getProjectSourceFiles(final String userId, final long projectId) {
    List<String> result = new ArrayList<String>();
    try {
      getProjectFiles(userId, projectId, "", true, result);
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
      prep.setDate(1, modDate);
      prep.setLong(2, projectId);
      prep.executeUpdate();
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, null, e);
    }
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
        if ((theFile.lastModified() + TWENTYFOURHOURS) < System.currentTimeMillis()) {
          // Yes backup, which in this case means we rename the file
          File renamedFile = new File(storageRoot.get() + "/" + userId + "/" + projectId + "/" + fileName +
                                      "." + formattedTime() + ".backup");
          if (!theFile.renameTo(renamedFile)) {
            throw CrashReport.createAndLogError(LOG, null,
                collectProjectErrorInfo(userId, projectId, fileName),
                new RuntimeException("File Rename for Backup Failed"));
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
      return new String(downloadRawFile(userId, projectId, fileName), encoding);
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
                                                 @Nullable String zipName) throws IOException {
    int fileCount = 0;
    ByteArrayOutputStream zipFile = new ByteArrayOutputStream();
    ZipOutputStream out = new ZipOutputStream(zipFile);
    List<String> sources = getProjectSourceFiles(userId, projectId);
    for (String fileName : sources) {
      byte [] data = downloadRawUserFile(userId, fileName);
      out.putNextEntry(new ZipEntry(fileName));
      out.write(data, 0, data.length);
      fileCount++;
    }
    if (includeProjectHistory) {
      String history = getProjectHistory(userId, projectId);
      byte [] data = history.getBytes(StorageUtil.DEFAULT_CHARSET);
      out.putNextEntry(new ZipEntry(FileExporter.REMIX_INFORMATION_FILE_PATH));
      out.write(data, 0, data.length);
      out.closeEntry();
      fileCount++;
    }
    if (includeAndroidKeystore) {
      byte [] data = downloadRawUserFile(userId, "android.keystore");
      if (data != null) {
        out.putNextEntry(new ZipEntry("android.keystore"));
        out.write(data, 0, data.length);
        out.closeEntry();
        fileCount++;
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
  public Motd getCurrentMotd() {
    // TBD
    return new Motd(1, "None", "No MOTD");
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
    // Not Implemented Yet
    return "";
  }

  @Override
  public void storeIpAddressByKey(final String key, final String ipAddress) {
    // Not Implemented Yet
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
      conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
      PreparedStatement prep = conn.prepareStatement("insert into nonce (nonce, userid, projectid, timestamp)" +
          " values (?, ?, ?, ?)");
      prep.setString(1, nonceValue);
      prep.setString(2, userId);
      prep.setLong(3, projectId);
      prep.setDate(4, new java.sql.Date(System.currentTimeMillis()));
      prep.executeUpdate();
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null,
          collectUserProjectErrorInfo(userId, projectId), e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
        }
      }
    }
  }

  @Override
  public Nonce getNoncebyValue(String nonceValue) {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
      PreparedStatement prep = conn.prepareStatement("select * from nonce where nonce = ?");
      prep.setString(1, nonceValue);
      ResultSet rs = prep.executeQuery();
      if (rs.next()) {
        return (new Nonce(rs.getString("nonce"),
            rs.getString("userid"),
            rs.getLong("projectid"),
            new java.util.Date(rs.getDate("timestamp").getTime())));
      } else {
        return null;
      }
    }
    catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, null, e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
        }
      }
    }
  }

  // Cleanup expired nonces which are older then 3 hours. Normal Nonce lifetime
  // is 2 hours. So for one hour they persist and return "link expired" instead of
  // "link not found" (after the object itself is removed).

  @Override
  public void cleanupNonces() {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
      PreparedStatement prep = conn.prepareStatement("delete from nonce where timestamp < ?");
      prep.setDate(1, new java.sql.Date(System.currentTimeMillis() - 3*3600*1000));
      prep.executeUpdate();
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, null, e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
        }
      }
    }
  }

  @Override
  public PWData createPWData(final String email) {
    Connection conn = null;
    try {
      long ts = System.currentTimeMillis();
      conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
      String uuid = UUID.randomUUID().toString();
      PreparedStatement prep = conn.prepareStatement("insert into pwdata (uuid, email, timestamp) " +
        "values (?, ?, ?)");
      prep.setString(1, uuid);
      prep.setString(2, email);
      prep.setDate(3, new java.sql.Date(ts));
      prep.executeUpdate();
      PWData pwData = new PWData();
      pwData.id = uuid;
      pwData.email = email;
      pwData.timestamp = new Date(ts);
      return pwData;
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, null, e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
        }
      }
    }
  }

  @Override
  public PWData findPWData(final String uid) {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
      String uuid = UUID.randomUUID().toString();
      PreparedStatement prep = conn.prepareStatement("select * from pwdata where uuid = ?");
      prep.setString(1, uuid);
      ResultSet rs = prep.executeQuery();
      if (rs.next()) {
        PWData pwData = new PWData();
        pwData.id = uuid;
        pwData.email = rs.getString("email");
        pwData.timestamp = new java.util.Date(rs.getDate("timestamp").getTime());
        return pwData;
      } else {
        return null;
      }
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, null, e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
        }
      }
    }
  }

  // Remove expired PWData elements from the datastore
  @Override
  public void cleanuppwdata() {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection("jdbc:sqlite:" + USER_DATABASE);
      long ts = System.currentTimeMillis() - 3600*1000; // An Hour Ago
      PreparedStatement prep = conn.prepareStatement("delete from pwdata where timestamp < ?");
      prep.setDate(1, new java.sql.Date(ts));
      prep.executeUpdate();
    } catch (SQLException e) {
      throw CrashReport.createAndLogError(LOG, null, null, e);
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (Exception e) {
        }
      }
    }
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

}
