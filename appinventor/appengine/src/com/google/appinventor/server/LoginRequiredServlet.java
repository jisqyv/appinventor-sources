// -*- mode: java; c-basic-offset: 2; -*-
// Copyright 2009-2011 Google, All Rights reserved
// Copyright 2011-2014 MIT, All rights reserved
// Released under the MIT License https://raw.github.com/mit-cml/app-inventor/master/mitlicense.txt

/*
 * OpenID LoginRequired Servlet -- Create a Login page for OpenID users.
 */

package com.google.appinventor.server;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletConfig;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.ServletException;

import java.io.PrintWriter;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Map;
import java.util.HashMap;

import com.google.appengine.api.memcache.MemcacheService;
import com.google.appengine.api.memcache.MemcacheServiceFactory;
import com.google.appengine.api.memcache.Expiration;

import com.google.appengine.api.users.User;
import com.google.appengine.api.users.UserService;
import com.google.appengine.api.users.UserServiceFactory;

@SuppressWarnings("unchecked")
public class LoginRequiredServlet extends HttpServlet {

  private static final UserService userService = UserServiceFactory.getUserService();

  public void init(ServletConfig config) throws ServletException {
    super.init(config);
  }

  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    resp.setContentType("text/html");
    PrintWriter out = resp.getWriter();
    String [] components = req.getRequestURI().split("/");
    User apiUser = userService.getCurrentUser();
    if (components[components.length-1].equals("check")) { // Verify we have an email field
      if (apiUser.getEmail().equals("")) {           // Provider didn't give us an email
        resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        out.println("OpenID Provider did not supply an e-mail address, which we require.");
        return;
      } else {                  // We are good, redirect to the real service
        resp.sendRedirect("/"); // Off to Ode we go!
      }
    }

    out.println("<html><head><title>Select Your OpenID Provider</title></head><body>");
    out.println("<h1>Please Select Your OpenID Provider</h1>");
    out.println("<form method=POST action=\"" + req.getRequestURI() + "\">");
    out.println("<select name=provider>");
    out.println("<option value=\"yahoo.com\">YaHoo</option>");
    out.println("<option value=\"https://www.google.com/accounts/o8/id\">Google</option>");
    out.println("<option value=\"other\">Other -- Fill in URL below</option>");
    out.println("</select><br /><br />");
    out.println("If \"Other\" selected: <input type=text name=other value=\"\"><br/><br/>");
    out.println("<input type=submit value=\"Login\">");
    out.println("</form>");
    out.println("</body></html>");
//    out.println(userService.createLoginURL(/, null, "yahoo.com", null));
  }

  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    BufferedReader input = new BufferedReader(new InputStreamReader(req.getInputStream()));
    String queryString = input.readLine();
    PrintWriter out = resp.getWriter();

    if (queryString == null) {
      out.println("queryString is null");
      return;
    }

    HashMap<String, String> params = getQueryMap(queryString);
    String provider = params.get("provider");
    if (provider == null) {
      out.println("no key");
      return;
    }
    if (provider.equals("other")) {
      provider = params.get("other");
      if (provider == null) {
        out.println("no key 2");
        return;
      }
    }
    String uri = userService.createLoginURL(req.getRequestURI() + "/check", null, provider, null);
    resp.sendRedirect(uri);
  }

  public void destroy() {
    super.destroy();
  }

  private static HashMap<String, String> getQueryMap(String query)  {
    String[] params = query.split("&");
    HashMap<String, String> map = new HashMap<String, String>();
    for (String param : params)  {
      String [] nvpair = param.split("=");
      if (nvpair.length <= 1) {
        map.put(nvpair[0], "");
      } else
        map.put(nvpair[0], nvpair[1]);
    }
    return map;
  }

}
