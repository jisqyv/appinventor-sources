// -*- mode: java; c-basic-offset: 2; -*-
// Copyright 2009-2011 Google, All Rights reserved
// Copyright 2011-2012 MIT, All rights reserved
// Released under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

package com.google.appinventor.server.storage;

import java.util.Date;

/**
 * Classes for the data objects that are stored in the Objectify database.
 *
 * TODO(user): for now I just defined a bunch of classes (parallel
 * to the ones in the old ode.proto). It might be
 * worth considering whether to make these classes extend DAOBasic (does it buy
 * us anything) and whether to add any methods for manipulating the objects.
 *
 * TODO(user): consider separating these out into individual class
 * files - more Java-y?
 *
 * @author sharon@google.com (Sharon Perl)
 *
 */

public class StoredData {

  // Data Structure to keep track of url's emailed out for password
  // setting and reseting. The Id (which is a UUID) is part of the URL
  // that is mailed out.

  public static final class PWData {
    public String id;               // "Secret" URL part
    public Date timestamp;          // So we know when to expire this objects
    public String email;            // Email of account in question
  }
}
