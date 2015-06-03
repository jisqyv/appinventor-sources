package edu.mit.appinventor;

import org.ini4j.Wini;

import java.io.File;
import java.io.IOException;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class StartSystem {

    private static final long expiration = 1441080000000L;  // September 1, 2015 Midnight UTC

    private static String storage = null;

    public static void main(String [] argv) {
      File execDir = new File(new File(StartSystem.class.getProtectionDomain().getCodeSource().getLocation().getPath()).getParent());
      Process s = null;
      Process build = null;
      String port = "8888";
      String mailhost = null;
      String mailuser = null;
      String mailpassword = null;
      boolean useStartTls = false;

      // Expiration Check
      if (System.currentTimeMillis() > expiration) {
          System.err.println("This copy of the Local App Inventor Server has expired, please get an updated version");
          System.exit(1);
      } else {
          System.err.println("This copy of MIT App Inventor expires on: " + new java.util.Date(expiration));
      }

      List<String> pArgs = new ArrayList<String>();
      pArgs.add("java");

      try {
          Wini parser = new Wini(new File("appinventor.ini"));
          storage = parser.get("main", "storage");
          mailhost = parser.get("mail", "host");
          mailuser = parser.get("mail", "user");
          mailpassword = parser.get("mail", "password");
          String stls = parser.get("mail", "starttls");
          if ((stls != null) && (stls.equals("true"))) {
              pArgs.add("-Dmail.smtp.starttls.enable=true");
          }
          String smtpport = parser.get("mail", "port");
          if (port != null) {
              pArgs.add("-Dmail.smtp.port=" + smtpport);
          }
          String keystore = parser.get("mail", "keystore");
          if (keystore != null) {
              pArgs.add("-Djavax.net.ssl.trustStore=" + keystore);
          }
      } catch (IOException e) {
          // Probably don't have ini file, non fatal
      }

      if (argv.length < 1) {
          if (storage == null) {
              System.err.println("Usage: java -jar starter.jar <path-to-root-storage>");
              System.exit(1);
          }
      } else {
          storage = argv[0];    // Command line overrides
      }

      pArgs.add("-Dstorage.root=" + storage);

      if (mailhost != null) {
          pArgs.add("-Dmail.smtp.host=" + mailhost);
      }
      if (mailuser != null) {
          pArgs.add("-Dmail.smtp.user=" + mailuser);
      }
      if (mailpassword != null) {
          pArgs.add("-Dmail.smtp.password=" + mailpassword);
      }
      pArgs.add("-jar");
      pArgs.add("jetty-runner.jar");
      pArgs.add("--port");
      pArgs.add(port);
      pArgs.add("appinventor.xml");

      ProcessBuilder server = new ProcessBuilder(pArgs);
      server.inheritIO();
      server.directory(execDir);

      File buildserverLibs = new File(execDir.getPath() + "/buildserver");
      File [] fileList = buildserverLibs.listFiles();
      if (fileList == null) {
          System.err.println("Could not find buildserver libraries.");
          System.exit(1);
      }
      String cp = "";
      boolean first = true;
      for (File file: fileList) {
          if (file.isFile()) {
              if (first) {
                  cp += file.getPath();
                  first = false;
              } else {
                  cp += File.pathSeparator + file.getPath();
              }
          }
      }

      String maxMem = "-Xmx1828m";
      ProcessBuilder buildserver = null;
      if (System.getProperty("os.name").startsWith("Windows")) {
          maxMem = "-Xmx1024m";
          buildserver = new ProcessBuilder("java", maxMem, "-cp", cp,
            "com.google.appinventor.buildserver.BuildServer","--dexCacheDir",
            "/tmp/dxcache", "--childProcessRamMb", "1024");
      } else {
          buildserver = new ProcessBuilder("java", maxMem, "-cp", cp,
            "com.google.appinventor.buildserver.BuildServer","--dexCacheDir",
            "/tmp/dxcache");
      }
      buildserver.inheritIO();
      buildserver.directory(execDir);

      try {
          s = server.start();
          build = buildserver.start();
      } catch (IOException e) {
          System.exit(1);
      }
      try {
          s.waitFor();
          build.waitFor();
      } catch (InterruptedException e) {
      }


    }

}
