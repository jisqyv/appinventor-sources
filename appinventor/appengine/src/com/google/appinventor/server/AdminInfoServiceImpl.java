// -*- mode: java; c-basic-offset: 2; -*-
// Copyright 2015 MIT, All rights reserved
// Released under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

package com.google.appinventor.server;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import com.google.appinventor.server.flags.Flag;
import com.google.appinventor.server.storage.StorageIo;
import com.google.appinventor.server.storage.StorageIoInstanceHolder;
import com.google.appinventor.shared.rpc.AdminInterfaceException;
import com.google.appinventor.shared.rpc.user.Config;
import com.google.appinventor.shared.rpc.admin.AdminUser;
import com.google.appinventor.shared.rpc.admin.AdminInfoService;
import com.google.appinventor.server.util.PasswordHash;

/**
 * Implementation of the user information service.
 *
 * <p>Note that this service must be state-less so that it can be run on
 * multiple servers.
 *
 */
public class AdminInfoServiceImpl extends OdeRemoteServiceServlet implements AdminInfoService {

  // Storage of user settings
  private final transient StorageIo storageIo = StorageIoInstanceHolder.INSTANCE;

  /**
   * Returns a list of AdminUsers, up to 20, based on the starting
   * point.
   */

    @Override
    public List<AdminUser> searchUsers(String startingPoint) {
      if (!userInfoProvider.getIsAdmin()) {
          throw new IllegalArgumentException("Unauthorized.");
      }
      return storageIo.searchUsers(startingPoint);
    }

    @Override
    public void storeUser(AdminUser user) throws AdminInterfaceException {
      if (!userInfoProvider.getIsAdmin()) {
          throw new IllegalArgumentException("Unauthorized.");
      }
      // This is a bit of a kludge
      // We hash the password here, replacing it in place
      String password = user.getPassword();
      String hashedPassword = "";
      if (password != null && !password.equals("")) {
          try {
              hashedPassword = PasswordHash.createHash(password);
              user.setPassword(hashedPassword);
          } catch (NoSuchAlgorithmException e) {
              throw new IllegalArgumentException("Error hashing password");
          } catch (InvalidKeySpecException e) {
              throw new IllegalArgumentException("Error hashing password");
          }
      }
      storageIo.storeUser(user);
    }

}
