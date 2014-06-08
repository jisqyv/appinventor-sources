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
import java.net.URLDecoder;
import java.util.Map;
import java.util.HashMap;

import com.google.appengine.api.memcache.MemcacheService;
import com.google.appengine.api.memcache.MemcacheServiceFactory;
import com.google.appengine.api.memcache.Expiration;

import com.google.appengine.api.users.User;
import com.google.appengine.api.users.UserService;
import com.google.appengine.api.users.UserServiceFactory;

import com.google.appinventor.server.storage.StorageIo;
import com.google.appinventor.server.storage.StorageIoInstanceHolder;
import com.google.appinventor.server.storage.StoredData.PWData;

@SuppressWarnings("unchecked")
public class LoginServlet extends HttpServlet {

  private final StorageIo storageIo = StorageIoInstanceHolder.INSTANCE;

  public void init(ServletConfig config) throws ServletException {
    super.init(config);
  }

  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    resp.setContentType("text/html");
    PrintWriter out = resp.getWriter();

    String [] components = req.getRequestURI().split("/");
    String page = getPage(req);
    String error = (String) req.getSession().getAttribute("error");

    if (page.equals("setpw")) {
      String uid = getParam(req);
      if (uid == null) {
        fail(req, resp, "Invalid Set Password Link");
        return;
      }
      PWData data = storageIo.findPWData(uid);
      if (data == null) {
        fail(req, resp, "Invalid Set Password Link");
        return;
      }
      req.getSession().setAttribute("email", data.email); // This effectively logs us in!
      out.println("<html><head><title>Set Your Password</title></head><body>\n");
      out.println("<h1>Set Your Password</h1>\n");
      out.println("<form method=POST action=\"" + req.getRequestURI() + "\">");
      out.println("<input type=password name=password value=\"\"><br />\n");
      out.println("<input type=Submit value=\"Set Password\">\n");
      out.println("</form>\n");
      return;
    }

    out.println("<html><head><title>Please Login</title></head><body>\n");
    out.println("<h1>Please Login</h1>\n");
    if (error != null) {
      req.getSession().removeAttribute("error");
      out.println("<b>Invalid Login Attempt: " + error + "</b><br /><br />\n");
    }
    out.println("<form method=POST action=\"" + req.getRequestURI() + "\">");
    out.println("<table>\n");
    out.println("<tr><td>Email Address</td><td><input type=text name=email value=\"\"></td></tr>\n");
    out.println("<tr><td>Password</td><td><input type=password name=password value=\"\"></td></tr>\n");
    out.println("</table>\n");
    out.println("<input type=Submit value=\"Login\">\n");
    out.println("</form>\n");
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
    String email = params.get("email");
    String password = params.get("password"); // We don't check it now
    if (email != null)
      email = URLDecoder.decode(email);
    if (password != null)
      password = URLDecoder.decode(password);
    if (!password.equals("magic")) { // Kludge for now, static password for all
      fail(req, resp, "Invalid Static Password");
      return;
    }

    req.getSession().setAttribute("email", email);

    String uri = "/";
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

  // Note: Urls in this servlet are of the form /login/<param>/<page>
  // The page identifier is *after* the parameter, if there is one.

  private String getPage(HttpServletRequest req) {
    String [] components = req.getRequestURI().split("/");
    return components[components.length-1];
  }

  private String getParam(HttpServletRequest req) {
    String [] components = req.getRequestURI().split("/");
    if (components.length < 2)
      return null;
    return components[components.length-2];
  }

  private void fail(HttpServletRequest req, HttpServletResponse resp, String error) throws IOException {
    req.getSession().setAttribute("error", error);
    req.getSession().removeAttribute("email"); // Make sure we are not logged in
    resp.sendRedirect("/login/");
    return;
  }
}
