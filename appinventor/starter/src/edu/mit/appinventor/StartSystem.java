package edu.mit.appinventor;

import java.io.File;

public class StartSystem {
    public static void main(String [] argv) {
      System.out.println(new File(StartSystem.class.getProtectionDomain().getCodeSource().getLocation().getPath()));
    }
}
