// -*- mode: java; c-basic-offset: 2; -*-
// Copyright 2009-2011 Google, All Rights reserved
// Copyright 2011-2014 MIT, All rights reserved
// Released under the MIT License https://raw.github.com/mit-cml/app-inventor/master/mitlicense.txt

package com.google.appinventor.server;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletConfig;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.ServletException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import com.google.appengine.api.memcache.MemcacheService;
import com.google.appengine.api.memcache.MemcacheServiceFactory;
import com.google.appengine.api.memcache.Expiration;
import com.google.appengine.api.users.UserService;
import com.google.appengine.api.users.UserServiceFactory;

import com.google.appinventor.server.flags.Flag;
import com.google.appinventor.shared.rpc.user.User;
import com.google.appinventor.server.storage.StorageIo;
import com.google.appinventor.server.storage.StorageIoInstanceHolder;
import com.google.appinventor.server.storage.StoredData.PWData;
import com.google.appinventor.server.util.PasswordHash;

/**
 * LoginServlet -- Handle logging someone in using an email address for a login
 * name and a password, which is stored hashed (and salted). Facilities are
 * provided to e-mail a password to an e-mail address both to set one up the
 * first time and to recover a lost password.
 *
 * This implementation uses a helper server to send mail. It does a webservices
 * transaction (REST/POST) to the server with the email address and reset url.
 * The helper server then formats the e-mail message and sends it. The source
 * code is in misc/passwordmail/...
 *
 * @author jis@mit.edu (Jeffrey I. Schiller)
 */
@SuppressWarnings("unchecked")
public class LoginServlet extends HttpServlet {

  private final StorageIo storageIo = StorageIoInstanceHolder.INSTANCE;
  private static final Logger LOG = Logger.getLogger(LoginServlet.class.getName());
  private static final Flag<String> mailServer = Flag.createFlag("localauth.mailserver", "");
  private static final Flag<String> password = Flag.createFlag("localauth.mailserver.password", "");
  private static final Flag<Boolean> useGoogle = Flag.createFlag("auth.usegoogle", true);
  private static final Flag<Boolean> useLocal = Flag.createFlag("auth.uselocal", false);
  private static final UserService userService = UserServiceFactory.getUserService();

  public void init(ServletConfig config) throws ServletException {
    super.init(config);
  }

  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    resp.setContentType("text/html");
    PrintWriter out = resp.getWriter();

    String [] components = req.getRequestURI().split("/");
    String page = getPage(req);
    String error = (String) req.getSession().getAttribute("error");

    if (page.equals("google")) {
      // We get here after we have gone through the Google Login page
      // This is arranged via a security-constraint setup in web.xml
      com.google.appengine.api.users.User apiUser = userService.getCurrentUser();
      if (apiUser == null) {  // Hmmm. I don't think this should happen
        fail(req, resp, "Google Authentication Failed"); // Not sure what else to do
        return;
      }
      String email = apiUser.getEmail();
      User user = storageIo.getUserFromEmail(email);
      req.getSession().setAttribute("userid", user.getUserId()); // This effectively logs us in!
      if (userService.isUserAdmin()) {                           // If Google says you are an admin
        req.getSession().setAttribute("isadmin", true);          // Tell the session we are admin
      }
      resp.sendRedirect("/");
    } else {
      if (useLocal.get() == false) {
        if (useGoogle.get() == false) {
          out.println("<html><head><title>Error</title></head>\n");
          out.println("<body><h1>App Inventor is Mis-Configured</h1>\n");
          out.println("<p>This instance of App Inventor has no authentication mechanism configured.</p>\n");
          out.println("</body>\n");
          out.println("</html>\n");
          return;
        }
        resp.sendRedirect("/login/google");
        return;
      }
    }

    // If we get here, local accounts are supported

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
      LOG.info("setpw email = " + data.email);
      User user = storageIo.getUserFromEmail(data.email);
      req.getSession().setAttribute("userid", user.getUserId()); // This effectively logs us in!
      out.println("<html><head><title>Set Your Password</title></head><body>\n");
      out.println("<h1>Set Your Password</h1>\n");
      out.println("<form method=POST action=\"" + req.getRequestURI() + "\">");
      out.println("<input type=password name=password value=\"\"><br />\n");
      out.println("<input type=Submit value=\"Set Password\">\n");
      out.println("</form>\n");
      storageIo.cleanuppwdata();
      return;
    } else if (page.equals("linksent")) {
      out.println("<html><head><title>Link Sent</title></head>\n");
      out.println("<body>\n");
      out.println("<h1>Link Sent</h1>\n");
      out.println("<p>Check your e-mail for a link to login and set/change your password.</p>\n");
      return;
    } else if (page.equals("sendlink")) {
      out.println("<head><title>Request Password Setup or Reset</title></head>\n");
      out.println("<body>\n");
      out.println("<h1>Request a Password Setup or Reset Link</h1>\n");
      out.println("<p>You can setup your first password or change your password if you forgot it here.</p>\n");
      out.println("<form method=POST action=\"" + req.getRequestURI() + "\">\n");
      out.println("Enter your Email Address:&nbsp;<input type=text name=email value=\"\"><br />\n");
      out.println("<input type=submit value=\"Send Link\">\n");
      out.println("</form>\n");
      return;
    }

    out.println("<html><head><title>Please Login</title></head><body>\n");
    out.println("<h1>Please Login</h1>\n");
    if (error != null) {
      req.getSession().removeAttribute("error");
      out.println("<b>Error: " + error + "</b><br /><br />\n");
    }
    out.println("<form method=POST action=\"" + req.getRequestURI() + "\">");
    out.println("<table>\n");
    out.println("<tr><td>Email Address</td><td><input type=text name=email value=\"\"></td></tr>\n");
    out.println("<tr><td>Password</td><td><input type=password name=password value=\"\"></td></tr>\n");
    out.println("</table>\n");
    out.println("<input type=Submit value=\"Login\">\n");
    out.println("</form>\n");
    out.println("<p><a href=\"/login/sendlink\">Click Here to Recover or Set your Password</a></p>\n");
    if (useGoogle.get() == true) {
      out.println("<p><a href=\"/login/google\">Click Here to use your Google Account to login</a></p>\n");
    }
    out.println("</body></html\n");
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
    String page = getPage(req);
    if (page.equals("sendlink")) {
      String email = params.get("email");
      if (email == null) {
        fail(req, resp, "No Email Address Provided");
        return;
      }
      // Send email here, for now we put it in the error string and redirect
      PWData pwData = storageIo.createPWData(email);
      if (pwData == null) {
        fail(req, resp, "Internal Error");
        return;
      }
      String link = trimPage(req) + pwData.id + "/setpw";
      sendmail(email, link);
      resp.sendRedirect("/login/linksent/");
//      req.getSession().setAttribute("error", link);
//      resp.sendRedirect("/");
      storageIo.cleanuppwdata();
      return;
    } else if (page.equals("setpw")) {
      String userid = (String) req.getSession().getAttribute("userid");
      if (userid == null) {
        fail(req, resp, "Session Timed Out");
        return;
      }
      User user = storageIo.getUser(userid);
      String password = params.get("password");
      if (password == null) {
        fail(req, resp, "No Password Provided");
        return;
      }
      String hashedPassword;
      try {
        hashedPassword = PasswordHash.createHash(password);
      } catch (NoSuchAlgorithmException e) {
        fail(req, resp, "System Error hashing password");
        return;
      } catch (InvalidKeySpecException e) {
        fail(req, resp, "System Error hashing password");
        return;
      }

      storageIo.setUserPassword(user.getUserId(),  hashedPassword);
      resp.sendRedirect("/");   // Logged in, go to service
      return;
    }

    String email = params.get("email");
    String password = params.get("password"); // We don't check it now
    User user = storageIo.getUserFromEmail(email);
    boolean validLogin = false;

    String hash = user.getPassword();
    if (hash == null) {
      fail(req, resp, "No Password Set for User");
      return;
    }

    try {
      validLogin = PasswordHash.validatePassword(password, hash);
    } catch (NoSuchAlgorithmException e) {
    } catch (InvalidKeySpecException e) {
    }

    if (!validLogin) {
      fail(req, resp, "Invalid Password");
      return;
    }

    req.getSession().setAttribute("userid", user.getUserId());

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
        map.put(nvpair[0], URLDecoder.decode(nvpair[1]));
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

  private String trimPage(HttpServletRequest req) {
    String [] components = req.getRequestURL().toString().split("/");
    StringBuffer sb = new StringBuffer();
    for (int i = 0; i < components.length-1; i++)
      sb.append(components[i] + "/");
    return sb.toString();
  }

  private void fail(HttpServletRequest req, HttpServletResponse resp, String error) throws IOException {
    req.getSession().setAttribute("error", error);
    req.getSession().removeAttribute("email"); // Make sure we are not logged in
    resp.sendRedirect("/login/");
    return;
  }

  private void sendmail(String email, String url) {
    try {
      String tmailServer = mailServer.get();
      if (tmailServer.equals("")) { // No mailserver = no mail!
        return;
      }
      URL mailServerUrl = new URL(tmailServer);
      HttpURLConnection connection = (HttpURLConnection) mailServerUrl.openConnection();
      connection.setDoOutput(true);
      connection.setRequestMethod("POST");
      PrintWriter stream = new PrintWriter(connection.getOutputStream());
      stream.write("email=" + URLEncoder.encode(email) + "&url=" + URLEncoder.encode(url) +
          "&pass=" + password.get());
      stream.flush();
      stream.close();
      int responseCode = 0;
      responseCode = connection.getResponseCode();
      if (responseCode != HttpURLConnection.HTTP_OK) {
        LOG.warning("mailserver responded with code = " + responseCode);
        // Nothing else we can do here...
      }
    } catch (MalformedURLException e) {
    } catch (IOException e) {
    }
  }
}
