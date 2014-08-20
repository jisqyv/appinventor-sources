package edu.mit.appinventor;

import java.io.File;
import java.io.IOException;

public class StartSystem {
    public static void main(String [] argv) {
      File execDir = new File(new File(StartSystem.class.getProtectionDomain().getCodeSource().getLocation().getPath()).getParent());
      Process s = null;
      Process build = null;
      String port = "8888";

      if (argv.length < 1) {
          System.err.println("Usage: java -jar starter.jar <path-to-root-storage> [port]");
          System.exit(1);
      }

      if (argv.length == 2) {   // We have a port argument
          port = argv[1];
      }

      ProcessBuilder server = new ProcessBuilder("java", ("-Dstorage.root=" + argv[0]), "-jar", "jetty-runner.jar", "--port", port, "appinventor.xml");
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
