package edu.mit.appinventor;

import org.ini4j.Wini;

import java.io.File;
import java.io.IOException;

public class StartSystem {

    private static String storage = null;

    public static void main(String [] argv) {
      File execDir = new File(new File(StartSystem.class.getProtectionDomain().getCodeSource().getLocation().getPath()).getParent());
      Process s = null;
      Process build = null;
      String port = "8888";

      try {
          Wini parser = new Wini(new File("appinventor.ini"));
          storage = parser.get("main", "storage");
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

      ProcessBuilder server = new ProcessBuilder("java", ("-Dstorage.root=" + storage), "-jar", "jetty-runner.jar", "--port", port, "appinventor.xml");
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
                  cp += ":" + file.getPath();
              }
          }
      }

      ProcessBuilder buildserver = new ProcessBuilder("java", "-Xmx1828m", "-cp", cp, "com.google.appinventor.buildserver.BuildServer",
        "--dexCacheDir", "/tmp/dxcache");
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
