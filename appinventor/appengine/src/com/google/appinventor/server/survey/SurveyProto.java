// Generated by the protocol buffer compiler.  DO NOT EDIT!
// NO CHECKED-IN PROTOBUF GENCODE
// source: survey.proto
// Protobuf Java Version: 4.28.1

package com.google.appinventor.server.survey;

public final class SurveyProto {
  private SurveyProto() {}
  static {
    com.google.protobuf.RuntimeVersion.validateProtobufGencodeVersion(
      com.google.protobuf.RuntimeVersion.RuntimeDomain.PUBLIC,
      /* major= */ 4,
      /* minor= */ 28,
      /* patch= */ 1,
      /* suffix= */ "",
      SurveyProto.class.getName());
  }
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  public interface surveytokenOrBuilder extends
      // @@protoc_insertion_point(interface_extends:survey.surveytoken)
      com.google.protobuf.MessageOrBuilder {

    /**
     * <code>required .survey.surveytoken.CommandType command = 1;</code>
     * @return Whether the command field is set.
     */
    boolean hasCommand();
    /**
     * <code>required .survey.surveytoken.CommandType command = 1;</code>
     * @return The command.
     */
    com.google.appinventor.server.survey.SurveyProto.surveytoken.CommandType getCommand();

    /**
     * <pre>
     * username or email of user
     * </pre>
     *
     * <code>optional string loginname = 2;</code>
     * @return Whether the loginname field is set.
     */
    boolean hasLoginname();
    /**
     * <pre>
     * username or email of user
     * </pre>
     *
     * <code>optional string loginname = 2;</code>
     * @return The loginname.
     */
    java.lang.String getLoginname();
    /**
     * <pre>
     * username or email of user
     * </pre>
     *
     * <code>optional string loginname = 2;</code>
     * @return The bytes for loginname.
     */
    com.google.protobuf.ByteString
        getLoginnameBytes();

    /**
     * <pre>
     * Where to send the user after the survey is complete
     * </pre>
     *
     * <code>optional string returnurl = 3;</code>
     * @return Whether the returnurl field is set.
     */
    boolean hasReturnurl();
    /**
     * <pre>
     * Where to send the user after the survey is complete
     * </pre>
     *
     * <code>optional string returnurl = 3;</code>
     * @return The returnurl.
     */
    java.lang.String getReturnurl();
    /**
     * <pre>
     * Where to send the user after the survey is complete
     * </pre>
     *
     * <code>optional string returnurl = 3;</code>
     * @return The bytes for returnurl.
     */
    com.google.protobuf.ByteString
        getReturnurlBytes();
  }
  /**
   * Protobuf type {@code survey.surveytoken}
   */
  public static final class surveytoken extends
      com.google.protobuf.GeneratedMessage implements
      // @@protoc_insertion_point(message_implements:survey.surveytoken)
      surveytokenOrBuilder {
  private static final long serialVersionUID = 0L;
    static {
      com.google.protobuf.RuntimeVersion.validateProtobufGencodeVersion(
        com.google.protobuf.RuntimeVersion.RuntimeDomain.PUBLIC,
        /* major= */ 4,
        /* minor= */ 28,
        /* patch= */ 1,
        /* suffix= */ "",
        surveytoken.class.getName());
    }
    // Use surveytoken.newBuilder() to construct.
    private surveytoken(com.google.protobuf.GeneratedMessage.Builder<?> builder) {
      super(builder);
    }
    private surveytoken() {
      command_ = 1;
      loginname_ = "";
      returnurl_ = "";
    }

    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return com.google.appinventor.server.survey.SurveyProto.internal_static_survey_surveytoken_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessage.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return com.google.appinventor.server.survey.SurveyProto.internal_static_survey_surveytoken_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              com.google.appinventor.server.survey.SurveyProto.surveytoken.class, com.google.appinventor.server.survey.SurveyProto.surveytoken.Builder.class);
    }

    /**
     * Protobuf enum {@code survey.surveytoken.CommandType}
     */
    public enum CommandType
        implements com.google.protobuf.ProtocolMessageEnum {
      /**
       * <code>DOSURVEY = 1;</code>
       */
      DOSURVEY(1),
      ;

      static {
        com.google.protobuf.RuntimeVersion.validateProtobufGencodeVersion(
          com.google.protobuf.RuntimeVersion.RuntimeDomain.PUBLIC,
          /* major= */ 4,
          /* minor= */ 28,
          /* patch= */ 1,
          /* suffix= */ "",
          CommandType.class.getName());
      }
      /**
       * <code>DOSURVEY = 1;</code>
       */
      public static final int DOSURVEY_VALUE = 1;


      public final int getNumber() {
        return value;
      }

      /**
       * @param value The numeric wire value of the corresponding enum entry.
       * @return The enum associated with the given numeric wire value.
       * @deprecated Use {@link #forNumber(int)} instead.
       */
      @java.lang.Deprecated
      public static CommandType valueOf(int value) {
        return forNumber(value);
      }

      /**
       * @param value The numeric wire value of the corresponding enum entry.
       * @return The enum associated with the given numeric wire value.
       */
      public static CommandType forNumber(int value) {
        switch (value) {
          case 1: return DOSURVEY;
          default: return null;
        }
      }

      public static com.google.protobuf.Internal.EnumLiteMap<CommandType>
          internalGetValueMap() {
        return internalValueMap;
      }
      private static final com.google.protobuf.Internal.EnumLiteMap<
          CommandType> internalValueMap =
            new com.google.protobuf.Internal.EnumLiteMap<CommandType>() {
              public CommandType findValueByNumber(int number) {
                return CommandType.forNumber(number);
              }
            };

      public final com.google.protobuf.Descriptors.EnumValueDescriptor
          getValueDescriptor() {
        return getDescriptor().getValues().get(ordinal());
      }
      public final com.google.protobuf.Descriptors.EnumDescriptor
          getDescriptorForType() {
        return getDescriptor();
      }
      public static final com.google.protobuf.Descriptors.EnumDescriptor
          getDescriptor() {
        return com.google.appinventor.server.survey.SurveyProto.surveytoken.getDescriptor().getEnumTypes().get(0);
      }

      private static final CommandType[] VALUES = values();

      public static CommandType valueOf(
          com.google.protobuf.Descriptors.EnumValueDescriptor desc) {
        if (desc.getType() != getDescriptor()) {
          throw new java.lang.IllegalArgumentException(
            "EnumValueDescriptor is not for this type.");
        }
        return VALUES[desc.getIndex()];
      }

      private final int value;

      private CommandType(int value) {
        this.value = value;
      }

      // @@protoc_insertion_point(enum_scope:survey.surveytoken.CommandType)
    }

    private int bitField0_;
    public static final int COMMAND_FIELD_NUMBER = 1;
    private int command_ = 1;
    /**
     * <code>required .survey.surveytoken.CommandType command = 1;</code>
     * @return Whether the command field is set.
     */
    @java.lang.Override public boolean hasCommand() {
      return ((bitField0_ & 0x00000001) != 0);
    }
    /**
     * <code>required .survey.surveytoken.CommandType command = 1;</code>
     * @return The command.
     */
    @java.lang.Override public com.google.appinventor.server.survey.SurveyProto.surveytoken.CommandType getCommand() {
      com.google.appinventor.server.survey.SurveyProto.surveytoken.CommandType result = com.google.appinventor.server.survey.SurveyProto.surveytoken.CommandType.forNumber(command_);
      return result == null ? com.google.appinventor.server.survey.SurveyProto.surveytoken.CommandType.DOSURVEY : result;
    }

    public static final int LOGINNAME_FIELD_NUMBER = 2;
    @SuppressWarnings("serial")
    private volatile java.lang.Object loginname_ = "";
    /**
     * <pre>
     * username or email of user
     * </pre>
     *
     * <code>optional string loginname = 2;</code>
     * @return Whether the loginname field is set.
     */
    @java.lang.Override
    public boolean hasLoginname() {
      return ((bitField0_ & 0x00000002) != 0);
    }
    /**
     * <pre>
     * username or email of user
     * </pre>
     *
     * <code>optional string loginname = 2;</code>
     * @return The loginname.
     */
    @java.lang.Override
    public java.lang.String getLoginname() {
      java.lang.Object ref = loginname_;
      if (ref instanceof java.lang.String) {
        return (java.lang.String) ref;
      } else {
        com.google.protobuf.ByteString bs = 
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        if (bs.isValidUtf8()) {
          loginname_ = s;
        }
        return s;
      }
    }
    /**
     * <pre>
     * username or email of user
     * </pre>
     *
     * <code>optional string loginname = 2;</code>
     * @return The bytes for loginname.
     */
    @java.lang.Override
    public com.google.protobuf.ByteString
        getLoginnameBytes() {
      java.lang.Object ref = loginname_;
      if (ref instanceof java.lang.String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        loginname_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }

    public static final int RETURNURL_FIELD_NUMBER = 3;
    @SuppressWarnings("serial")
    private volatile java.lang.Object returnurl_ = "";
    /**
     * <pre>
     * Where to send the user after the survey is complete
     * </pre>
     *
     * <code>optional string returnurl = 3;</code>
     * @return Whether the returnurl field is set.
     */
    @java.lang.Override
    public boolean hasReturnurl() {
      return ((bitField0_ & 0x00000004) != 0);
    }
    /**
     * <pre>
     * Where to send the user after the survey is complete
     * </pre>
     *
     * <code>optional string returnurl = 3;</code>
     * @return The returnurl.
     */
    @java.lang.Override
    public java.lang.String getReturnurl() {
      java.lang.Object ref = returnurl_;
      if (ref instanceof java.lang.String) {
        return (java.lang.String) ref;
      } else {
        com.google.protobuf.ByteString bs = 
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        if (bs.isValidUtf8()) {
          returnurl_ = s;
        }
        return s;
      }
    }
    /**
     * <pre>
     * Where to send the user after the survey is complete
     * </pre>
     *
     * <code>optional string returnurl = 3;</code>
     * @return The bytes for returnurl.
     */
    @java.lang.Override
    public com.google.protobuf.ByteString
        getReturnurlBytes() {
      java.lang.Object ref = returnurl_;
      if (ref instanceof java.lang.String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        returnurl_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }

    private byte memoizedIsInitialized = -1;
    @java.lang.Override
    public final boolean isInitialized() {
      byte isInitialized = memoizedIsInitialized;
      if (isInitialized == 1) return true;
      if (isInitialized == 0) return false;

      if (!hasCommand()) {
        memoizedIsInitialized = 0;
        return false;
      }
      memoizedIsInitialized = 1;
      return true;
    }

    @java.lang.Override
    public void writeTo(com.google.protobuf.CodedOutputStream output)
                        throws java.io.IOException {
      if (((bitField0_ & 0x00000001) != 0)) {
        output.writeEnum(1, command_);
      }
      if (((bitField0_ & 0x00000002) != 0)) {
        com.google.protobuf.GeneratedMessage.writeString(output, 2, loginname_);
      }
      if (((bitField0_ & 0x00000004) != 0)) {
        com.google.protobuf.GeneratedMessage.writeString(output, 3, returnurl_);
      }
      getUnknownFields().writeTo(output);
    }

    @java.lang.Override
    public int getSerializedSize() {
      int size = memoizedSize;
      if (size != -1) return size;

      size = 0;
      if (((bitField0_ & 0x00000001) != 0)) {
        size += com.google.protobuf.CodedOutputStream
          .computeEnumSize(1, command_);
      }
      if (((bitField0_ & 0x00000002) != 0)) {
        size += com.google.protobuf.GeneratedMessage.computeStringSize(2, loginname_);
      }
      if (((bitField0_ & 0x00000004) != 0)) {
        size += com.google.protobuf.GeneratedMessage.computeStringSize(3, returnurl_);
      }
      size += getUnknownFields().getSerializedSize();
      memoizedSize = size;
      return size;
    }

    @java.lang.Override
    public boolean equals(final java.lang.Object obj) {
      if (obj == this) {
       return true;
      }
      if (!(obj instanceof com.google.appinventor.server.survey.SurveyProto.surveytoken)) {
        return super.equals(obj);
      }
      com.google.appinventor.server.survey.SurveyProto.surveytoken other = (com.google.appinventor.server.survey.SurveyProto.surveytoken) obj;

      if (hasCommand() != other.hasCommand()) return false;
      if (hasCommand()) {
        if (command_ != other.command_) return false;
      }
      if (hasLoginname() != other.hasLoginname()) return false;
      if (hasLoginname()) {
        if (!getLoginname()
            .equals(other.getLoginname())) return false;
      }
      if (hasReturnurl() != other.hasReturnurl()) return false;
      if (hasReturnurl()) {
        if (!getReturnurl()
            .equals(other.getReturnurl())) return false;
      }
      if (!getUnknownFields().equals(other.getUnknownFields())) return false;
      return true;
    }

    @java.lang.Override
    public int hashCode() {
      if (memoizedHashCode != 0) {
        return memoizedHashCode;
      }
      int hash = 41;
      hash = (19 * hash) + getDescriptor().hashCode();
      if (hasCommand()) {
        hash = (37 * hash) + COMMAND_FIELD_NUMBER;
        hash = (53 * hash) + command_;
      }
      if (hasLoginname()) {
        hash = (37 * hash) + LOGINNAME_FIELD_NUMBER;
        hash = (53 * hash) + getLoginname().hashCode();
      }
      if (hasReturnurl()) {
        hash = (37 * hash) + RETURNURL_FIELD_NUMBER;
        hash = (53 * hash) + getReturnurl().hashCode();
      }
      hash = (29 * hash) + getUnknownFields().hashCode();
      memoizedHashCode = hash;
      return hash;
    }

    public static com.google.appinventor.server.survey.SurveyProto.surveytoken parseFrom(
        java.nio.ByteBuffer data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static com.google.appinventor.server.survey.SurveyProto.surveytoken parseFrom(
        java.nio.ByteBuffer data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static com.google.appinventor.server.survey.SurveyProto.surveytoken parseFrom(
        com.google.protobuf.ByteString data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static com.google.appinventor.server.survey.SurveyProto.surveytoken parseFrom(
        com.google.protobuf.ByteString data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static com.google.appinventor.server.survey.SurveyProto.surveytoken parseFrom(byte[] data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static com.google.appinventor.server.survey.SurveyProto.surveytoken parseFrom(
        byte[] data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static com.google.appinventor.server.survey.SurveyProto.surveytoken parseFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessage
          .parseWithIOException(PARSER, input);
    }
    public static com.google.appinventor.server.survey.SurveyProto.surveytoken parseFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessage
          .parseWithIOException(PARSER, input, extensionRegistry);
    }

    public static com.google.appinventor.server.survey.SurveyProto.surveytoken parseDelimitedFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessage
          .parseDelimitedWithIOException(PARSER, input);
    }

    public static com.google.appinventor.server.survey.SurveyProto.surveytoken parseDelimitedFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessage
          .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
    }
    public static com.google.appinventor.server.survey.SurveyProto.surveytoken parseFrom(
        com.google.protobuf.CodedInputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessage
          .parseWithIOException(PARSER, input);
    }
    public static com.google.appinventor.server.survey.SurveyProto.surveytoken parseFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessage
          .parseWithIOException(PARSER, input, extensionRegistry);
    }

    @java.lang.Override
    public Builder newBuilderForType() { return newBuilder(); }
    public static Builder newBuilder() {
      return DEFAULT_INSTANCE.toBuilder();
    }
    public static Builder newBuilder(com.google.appinventor.server.survey.SurveyProto.surveytoken prototype) {
      return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
    }
    @java.lang.Override
    public Builder toBuilder() {
      return this == DEFAULT_INSTANCE
          ? new Builder() : new Builder().mergeFrom(this);
    }

    @java.lang.Override
    protected Builder newBuilderForType(
        com.google.protobuf.GeneratedMessage.BuilderParent parent) {
      Builder builder = new Builder(parent);
      return builder;
    }
    /**
     * Protobuf type {@code survey.surveytoken}
     */
    public static final class Builder extends
        com.google.protobuf.GeneratedMessage.Builder<Builder> implements
        // @@protoc_insertion_point(builder_implements:survey.surveytoken)
        com.google.appinventor.server.survey.SurveyProto.surveytokenOrBuilder {
      public static final com.google.protobuf.Descriptors.Descriptor
          getDescriptor() {
        return com.google.appinventor.server.survey.SurveyProto.internal_static_survey_surveytoken_descriptor;
      }

      @java.lang.Override
      protected com.google.protobuf.GeneratedMessage.FieldAccessorTable
          internalGetFieldAccessorTable() {
        return com.google.appinventor.server.survey.SurveyProto.internal_static_survey_surveytoken_fieldAccessorTable
            .ensureFieldAccessorsInitialized(
                com.google.appinventor.server.survey.SurveyProto.surveytoken.class, com.google.appinventor.server.survey.SurveyProto.surveytoken.Builder.class);
      }

      // Construct using com.google.appinventor.server.survey.SurveyProto.surveytoken.newBuilder()
      private Builder() {

      }

      private Builder(
          com.google.protobuf.GeneratedMessage.BuilderParent parent) {
        super(parent);

      }
      @java.lang.Override
      public Builder clear() {
        super.clear();
        bitField0_ = 0;
        command_ = 1;
        loginname_ = "";
        returnurl_ = "";
        return this;
      }

      @java.lang.Override
      public com.google.protobuf.Descriptors.Descriptor
          getDescriptorForType() {
        return com.google.appinventor.server.survey.SurveyProto.internal_static_survey_surveytoken_descriptor;
      }

      @java.lang.Override
      public com.google.appinventor.server.survey.SurveyProto.surveytoken getDefaultInstanceForType() {
        return com.google.appinventor.server.survey.SurveyProto.surveytoken.getDefaultInstance();
      }

      @java.lang.Override
      public com.google.appinventor.server.survey.SurveyProto.surveytoken build() {
        com.google.appinventor.server.survey.SurveyProto.surveytoken result = buildPartial();
        if (!result.isInitialized()) {
          throw newUninitializedMessageException(result);
        }
        return result;
      }

      @java.lang.Override
      public com.google.appinventor.server.survey.SurveyProto.surveytoken buildPartial() {
        com.google.appinventor.server.survey.SurveyProto.surveytoken result = new com.google.appinventor.server.survey.SurveyProto.surveytoken(this);
        if (bitField0_ != 0) { buildPartial0(result); }
        onBuilt();
        return result;
      }

      private void buildPartial0(com.google.appinventor.server.survey.SurveyProto.surveytoken result) {
        int from_bitField0_ = bitField0_;
        int to_bitField0_ = 0;
        if (((from_bitField0_ & 0x00000001) != 0)) {
          result.command_ = command_;
          to_bitField0_ |= 0x00000001;
        }
        if (((from_bitField0_ & 0x00000002) != 0)) {
          result.loginname_ = loginname_;
          to_bitField0_ |= 0x00000002;
        }
        if (((from_bitField0_ & 0x00000004) != 0)) {
          result.returnurl_ = returnurl_;
          to_bitField0_ |= 0x00000004;
        }
        result.bitField0_ |= to_bitField0_;
      }

      @java.lang.Override
      public Builder mergeFrom(com.google.protobuf.Message other) {
        if (other instanceof com.google.appinventor.server.survey.SurveyProto.surveytoken) {
          return mergeFrom((com.google.appinventor.server.survey.SurveyProto.surveytoken)other);
        } else {
          super.mergeFrom(other);
          return this;
        }
      }

      public Builder mergeFrom(com.google.appinventor.server.survey.SurveyProto.surveytoken other) {
        if (other == com.google.appinventor.server.survey.SurveyProto.surveytoken.getDefaultInstance()) return this;
        if (other.hasCommand()) {
          setCommand(other.getCommand());
        }
        if (other.hasLoginname()) {
          loginname_ = other.loginname_;
          bitField0_ |= 0x00000002;
          onChanged();
        }
        if (other.hasReturnurl()) {
          returnurl_ = other.returnurl_;
          bitField0_ |= 0x00000004;
          onChanged();
        }
        this.mergeUnknownFields(other.getUnknownFields());
        onChanged();
        return this;
      }

      @java.lang.Override
      public final boolean isInitialized() {
        if (!hasCommand()) {
          return false;
        }
        return true;
      }

      @java.lang.Override
      public Builder mergeFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws java.io.IOException {
        if (extensionRegistry == null) {
          throw new java.lang.NullPointerException();
        }
        try {
          boolean done = false;
          while (!done) {
            int tag = input.readTag();
            switch (tag) {
              case 0:
                done = true;
                break;
              case 8: {
                int tmpRaw = input.readEnum();
                com.google.appinventor.server.survey.SurveyProto.surveytoken.CommandType tmpValue =
                    com.google.appinventor.server.survey.SurveyProto.surveytoken.CommandType.forNumber(tmpRaw);
                if (tmpValue == null) {
                  mergeUnknownVarintField(1, tmpRaw);
                } else {
                  command_ = tmpRaw;
                  bitField0_ |= 0x00000001;
                }
                break;
              } // case 8
              case 18: {
                loginname_ = input.readBytes();
                bitField0_ |= 0x00000002;
                break;
              } // case 18
              case 26: {
                returnurl_ = input.readBytes();
                bitField0_ |= 0x00000004;
                break;
              } // case 26
              default: {
                if (!super.parseUnknownField(input, extensionRegistry, tag)) {
                  done = true; // was an endgroup tag
                }
                break;
              } // default:
            } // switch (tag)
          } // while (!done)
        } catch (com.google.protobuf.InvalidProtocolBufferException e) {
          throw e.unwrapIOException();
        } finally {
          onChanged();
        } // finally
        return this;
      }
      private int bitField0_;

      private int command_ = 1;
      /**
       * <code>required .survey.surveytoken.CommandType command = 1;</code>
       * @return Whether the command field is set.
       */
      @java.lang.Override public boolean hasCommand() {
        return ((bitField0_ & 0x00000001) != 0);
      }
      /**
       * <code>required .survey.surveytoken.CommandType command = 1;</code>
       * @return The command.
       */
      @java.lang.Override
      public com.google.appinventor.server.survey.SurveyProto.surveytoken.CommandType getCommand() {
        com.google.appinventor.server.survey.SurveyProto.surveytoken.CommandType result = com.google.appinventor.server.survey.SurveyProto.surveytoken.CommandType.forNumber(command_);
        return result == null ? com.google.appinventor.server.survey.SurveyProto.surveytoken.CommandType.DOSURVEY : result;
      }
      /**
       * <code>required .survey.surveytoken.CommandType command = 1;</code>
       * @param value The command to set.
       * @return This builder for chaining.
       */
      public Builder setCommand(com.google.appinventor.server.survey.SurveyProto.surveytoken.CommandType value) {
        if (value == null) {
          throw new NullPointerException();
        }
        bitField0_ |= 0x00000001;
        command_ = value.getNumber();
        onChanged();
        return this;
      }
      /**
       * <code>required .survey.surveytoken.CommandType command = 1;</code>
       * @return This builder for chaining.
       */
      public Builder clearCommand() {
        bitField0_ = (bitField0_ & ~0x00000001);
        command_ = 1;
        onChanged();
        return this;
      }

      private java.lang.Object loginname_ = "";
      /**
       * <pre>
       * username or email of user
       * </pre>
       *
       * <code>optional string loginname = 2;</code>
       * @return Whether the loginname field is set.
       */
      public boolean hasLoginname() {
        return ((bitField0_ & 0x00000002) != 0);
      }
      /**
       * <pre>
       * username or email of user
       * </pre>
       *
       * <code>optional string loginname = 2;</code>
       * @return The loginname.
       */
      public java.lang.String getLoginname() {
        java.lang.Object ref = loginname_;
        if (!(ref instanceof java.lang.String)) {
          com.google.protobuf.ByteString bs =
              (com.google.protobuf.ByteString) ref;
          java.lang.String s = bs.toStringUtf8();
          if (bs.isValidUtf8()) {
            loginname_ = s;
          }
          return s;
        } else {
          return (java.lang.String) ref;
        }
      }
      /**
       * <pre>
       * username or email of user
       * </pre>
       *
       * <code>optional string loginname = 2;</code>
       * @return The bytes for loginname.
       */
      public com.google.protobuf.ByteString
          getLoginnameBytes() {
        java.lang.Object ref = loginname_;
        if (ref instanceof String) {
          com.google.protobuf.ByteString b = 
              com.google.protobuf.ByteString.copyFromUtf8(
                  (java.lang.String) ref);
          loginname_ = b;
          return b;
        } else {
          return (com.google.protobuf.ByteString) ref;
        }
      }
      /**
       * <pre>
       * username or email of user
       * </pre>
       *
       * <code>optional string loginname = 2;</code>
       * @param value The loginname to set.
       * @return This builder for chaining.
       */
      public Builder setLoginname(
          java.lang.String value) {
        if (value == null) { throw new NullPointerException(); }
        loginname_ = value;
        bitField0_ |= 0x00000002;
        onChanged();
        return this;
      }
      /**
       * <pre>
       * username or email of user
       * </pre>
       *
       * <code>optional string loginname = 2;</code>
       * @return This builder for chaining.
       */
      public Builder clearLoginname() {
        loginname_ = getDefaultInstance().getLoginname();
        bitField0_ = (bitField0_ & ~0x00000002);
        onChanged();
        return this;
      }
      /**
       * <pre>
       * username or email of user
       * </pre>
       *
       * <code>optional string loginname = 2;</code>
       * @param value The bytes for loginname to set.
       * @return This builder for chaining.
       */
      public Builder setLoginnameBytes(
          com.google.protobuf.ByteString value) {
        if (value == null) { throw new NullPointerException(); }
        loginname_ = value;
        bitField0_ |= 0x00000002;
        onChanged();
        return this;
      }

      private java.lang.Object returnurl_ = "";
      /**
       * <pre>
       * Where to send the user after the survey is complete
       * </pre>
       *
       * <code>optional string returnurl = 3;</code>
       * @return Whether the returnurl field is set.
       */
      public boolean hasReturnurl() {
        return ((bitField0_ & 0x00000004) != 0);
      }
      /**
       * <pre>
       * Where to send the user after the survey is complete
       * </pre>
       *
       * <code>optional string returnurl = 3;</code>
       * @return The returnurl.
       */
      public java.lang.String getReturnurl() {
        java.lang.Object ref = returnurl_;
        if (!(ref instanceof java.lang.String)) {
          com.google.protobuf.ByteString bs =
              (com.google.protobuf.ByteString) ref;
          java.lang.String s = bs.toStringUtf8();
          if (bs.isValidUtf8()) {
            returnurl_ = s;
          }
          return s;
        } else {
          return (java.lang.String) ref;
        }
      }
      /**
       * <pre>
       * Where to send the user after the survey is complete
       * </pre>
       *
       * <code>optional string returnurl = 3;</code>
       * @return The bytes for returnurl.
       */
      public com.google.protobuf.ByteString
          getReturnurlBytes() {
        java.lang.Object ref = returnurl_;
        if (ref instanceof String) {
          com.google.protobuf.ByteString b = 
              com.google.protobuf.ByteString.copyFromUtf8(
                  (java.lang.String) ref);
          returnurl_ = b;
          return b;
        } else {
          return (com.google.protobuf.ByteString) ref;
        }
      }
      /**
       * <pre>
       * Where to send the user after the survey is complete
       * </pre>
       *
       * <code>optional string returnurl = 3;</code>
       * @param value The returnurl to set.
       * @return This builder for chaining.
       */
      public Builder setReturnurl(
          java.lang.String value) {
        if (value == null) { throw new NullPointerException(); }
        returnurl_ = value;
        bitField0_ |= 0x00000004;
        onChanged();
        return this;
      }
      /**
       * <pre>
       * Where to send the user after the survey is complete
       * </pre>
       *
       * <code>optional string returnurl = 3;</code>
       * @return This builder for chaining.
       */
      public Builder clearReturnurl() {
        returnurl_ = getDefaultInstance().getReturnurl();
        bitField0_ = (bitField0_ & ~0x00000004);
        onChanged();
        return this;
      }
      /**
       * <pre>
       * Where to send the user after the survey is complete
       * </pre>
       *
       * <code>optional string returnurl = 3;</code>
       * @param value The bytes for returnurl to set.
       * @return This builder for chaining.
       */
      public Builder setReturnurlBytes(
          com.google.protobuf.ByteString value) {
        if (value == null) { throw new NullPointerException(); }
        returnurl_ = value;
        bitField0_ |= 0x00000004;
        onChanged();
        return this;
      }

      // @@protoc_insertion_point(builder_scope:survey.surveytoken)
    }

    // @@protoc_insertion_point(class_scope:survey.surveytoken)
    private static final com.google.appinventor.server.survey.SurveyProto.surveytoken DEFAULT_INSTANCE;
    static {
      DEFAULT_INSTANCE = new com.google.appinventor.server.survey.SurveyProto.surveytoken();
    }

    public static com.google.appinventor.server.survey.SurveyProto.surveytoken getDefaultInstance() {
      return DEFAULT_INSTANCE;
    }

    private static final com.google.protobuf.Parser<surveytoken>
        PARSER = new com.google.protobuf.AbstractParser<surveytoken>() {
      @java.lang.Override
      public surveytoken parsePartialFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws com.google.protobuf.InvalidProtocolBufferException {
        Builder builder = newBuilder();
        try {
          builder.mergeFrom(input, extensionRegistry);
        } catch (com.google.protobuf.InvalidProtocolBufferException e) {
          throw e.setUnfinishedMessage(builder.buildPartial());
        } catch (com.google.protobuf.UninitializedMessageException e) {
          throw e.asInvalidProtocolBufferException().setUnfinishedMessage(builder.buildPartial());
        } catch (java.io.IOException e) {
          throw new com.google.protobuf.InvalidProtocolBufferException(e)
              .setUnfinishedMessage(builder.buildPartial());
        }
        return builder.buildPartial();
      }
    };

    public static com.google.protobuf.Parser<surveytoken> parser() {
      return PARSER;
    }

    @java.lang.Override
    public com.google.protobuf.Parser<surveytoken> getParserForType() {
      return PARSER;
    }

    @java.lang.Override
    public com.google.appinventor.server.survey.SurveyProto.surveytoken getDefaultInstanceForType() {
      return DEFAULT_INSTANCE;
    }

  }

  private static final com.google.protobuf.Descriptors.Descriptor
    internal_static_survey_surveytoken_descriptor;
  private static final 
    com.google.protobuf.GeneratedMessage.FieldAccessorTable
      internal_static_survey_surveytoken_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\014survey.proto\022\006survey\"\202\001\n\013surveytoken\0220" +
      "\n\007command\030\001 \002(\0162\037.survey.surveytoken.Com" +
      "mandType\022\021\n\tloginname\030\002 \001(\t\022\021\n\treturnurl" +
      "\030\003 \001(\t\"\033\n\013CommandType\022\014\n\010DOSURVEY\020\001B3\n$c" +
      "om.google.appinventor.server.surveyB\013Sur" +
      "veyProto"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
        });
    internal_static_survey_surveytoken_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_survey_surveytoken_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessage.FieldAccessorTable(
        internal_static_survey_surveytoken_descriptor,
        new java.lang.String[] { "Command", "Loginname", "Returnurl", });
    descriptor.resolveAllFeaturesImmutable();
  }

  // @@protoc_insertion_point(outer_class_scope)
}
