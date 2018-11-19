// -*- mode: java; c-basic-offset: 2; -*-
// Copyright 2016 MIT, All rights reserved.
// This is unreleased code.

package com.google.appinventor.server.tokens;

import com.google.appinventor.server.flags.Flag;

import org.keyczar.Crypter;
import org.keyczar.util.Base64Coder;
import org.keyczar.exceptions.KeyczarException;

public class Token {

  private static Flag<String> tokenKey = Flag.createFlag("token.key", "");
  private static Crypter crypter;

  static {
    try {
      crypter = new Crypter(tokenKey.get());
    } catch (KeyczarException e) {
      e.printStackTrace();
    }
  }

  private Token() {
  }

  public static synchronized String makeSSOToken(String userId) {
    try {
      TokenProto.token newToken = TokenProto.token.newBuilder()
        .setCommand(TokenProto.token.CommandType.SSOLOGIN)
        .setUuid(userId)
        .setTs(System.currentTimeMillis()).build();
      return Base64Coder.encode(crypter.encrypt(newToken.toByteArray()));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static synchronized String makeAccountCreateToken(String userId, String name) {
    try {
      TokenProto.token newToken = TokenProto.token.newBuilder()
        .setCommand(TokenProto.token.CommandType.CREATEACCOUNT)
        .setUuid(userId)
        .setName(name)
        .setTs(System.currentTimeMillis()).build();
      return Base64Coder.encode(crypter.encrypt(newToken.toByteArray()));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static TokenProto.token verifyToken(String inToken) throws TokenException {
    try {
      byte [] decrypted = crypter.decrypt(Base64Coder.decode(inToken));
      TokenProto.token newToken = TokenProto.token.parseFrom(decrypted);
      return newToken;
    } catch (Exception e) {
      throw new TokenException(e.getMessage());
    }
  }
}
