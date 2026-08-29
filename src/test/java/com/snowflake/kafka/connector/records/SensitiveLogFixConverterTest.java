/*
 * Copyright (c) 2024 Snowflake Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.snowflake.kafka.connector.records;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.snowflake.kafka.connector.internal.LogCaptureAppender;
import com.snowflake.kafka.connector.internal.SnowflakeKafkaConnectorException;
import com.snowflake.kafka.connector.mock.MockSchemaRegistryClient;
import java.nio.charset.StandardCharsets;
import org.apache.kafka.connect.data.SchemaAndValue;
import org.junit.jupiter.api.Test;

/**
 * Red-green proofs for the sensitive-log-audit findings that live in the record-conversion path:
 *
 * <ul>
 *   <li><b>F1</b> RecordService.convertToJson (line ~451): must not concatenate the raw record
 *       value.
 *   <li><b>F4</b> SnowflakeAvroConverterWithoutSchemaRegistry (line ~84): must not log the raw
 *       decode exception message (it can carry a record-content fragment).
 *   <li><b>F5</b> SnowflakeAvroConverter (lines ~171 throw / ~181 log): must not surface the raw
 *       Avro decode exception message/toString.
 * </ul>
 *
 * The converters log through the base {@code SnowflakeConverter} logger; the assertions below run a
 * synthetic canary through each path and assert on the rendered log / thrown message.
 */
public class SensitiveLogFixConverterTest {

  private static final String CONVERTER_LOGGER = SnowflakeConverter.class.getName();

  /**
   * F1 — RecordService.convertToJson: the reachable conversion-failure branches must describe the
   * failure by <em>type</em>, never by echoing the raw value. (The audited line 448/451 is a
   * defensive switch fall-through; the reachable branches are the type-mismatch and unknown-class
   * ones, asserted here.)
   */
  @Test
  public void f1_convertToJson_doesNotEchoRawValue() {
    // A value whose runtime class has no corresponding Connect schema type reaches the
    // "unknown Java class" branch; assert the message names the class, not a raw value.
    Object unconvertible = new java.util.concurrent.atomic.AtomicReference<>("CANARY_F1_VALUE");
    SnowflakeKafkaConnectorException ex =
        assertThrows(
            SnowflakeKafkaConnectorException.class,
            () -> RecordService.convertToJson(null, unconvertible, false));
    for (Throwable t = ex; t != null; t = t.getCause()) {
      String m = String.valueOf(t.getMessage());
      assertFalse(
          m.contains("CANARY_F1_VALUE"),
          "convertToJson exception must not echo the raw record value: " + m);
    }
  }

  /**
   * F4 — SnowflakeAvroConverterWithoutSchemaRegistry: on a decode failure the ERROR log must carry
   * the topic + error class only, never the raw decode exception message (which can embed a
   * fragment of the record content). Red on the pre-fix code, which logged {@code e.getMessage()}.
   */
  @Test
  public void f4_avroWithoutSchemaRegistry_logsClassNotMessage() {
    LogCaptureAppender appender = LogCaptureAppender.attachTo(CONVERTER_LOGGER);
    try {
      // Not a valid Avro container -> DataFileReader ctor throws -> outer catch logs at ERROR.
      byte[] notAvro = "not-an-avro-container".getBytes(StandardCharsets.UTF_8);
      SchemaAndValue sv =
          new SnowflakeAvroConverterWithoutSchemaRegistry().toConnectData("topicF4", notAvro);
      // Still returns a broken record (unchanged behavior).
      assertTrue(((SnowflakeRecordContent) sv.value()).isBroken());

      // GREEN: new structural format present; RED on old format ("Failed to parse AVRO
      // record\n...").
      assertTrue(
          appender.anyMessageContains("Failed to parse AVRO record for topic topicF4:"),
          "expected sanitized ERROR log, got: " + appender.messages());
      // The sanitized log names only the exception class; it must not relay the raw decode message.
      assertFalse(
          appender.anyMessageContains("Failed to parse AVRO record\n"),
          "log must not use the old message-bearing format: " + appender.messages());
    } finally {
      appender.detach();
    }
  }

  /**
   * F5 (throw path) — SnowflakeAvroConverter with break-on-schema-registry-error=true: the
   * exception rethrown to the framework (task status) must carry the decode error class only, not
   * {@code e.toString()} of the Avro decode exception. Structural red-green: the pre-fix message
   * concatenated {@code "...record\n" + e.toString()} (contains a newline); the fixed message is a
   * single-line "Failed to parse AVRO record: &lt;class&gt;".
   */
  @Test
  public void f5_avroWithSchemaRegistry_breakOnError_throwsClassNotToString() throws Exception {
    MockSchemaRegistryClient client = new MockSchemaRegistryClient();
    SnowflakeAvroConverter converter = new SnowflakeAvroConverter();
    java.util.Map<String, String> configs = new java.util.HashMap<>();
    configs.put("schema.registry.url", "http://fake-url");
    configs.put(SnowflakeAvroConverter.BREAK_ON_SCHEMA_REGISTRY_ERROR, "true");
    converter.configure(configs, false);
    converter.setSchemaRegistry(client);

    // Valid SR header (magic + id) but a corrupted Avro body -> parseAvroWithSchema throws.
    byte[] good = client.getData();
    byte[] corrupt = good.clone();
    for (int i = 5; i < corrupt.length; i++) {
      corrupt[i] = (byte) 0xEE;
    }

    SnowflakeKafkaConnectorException ex =
        assertThrows(
            SnowflakeKafkaConnectorException.class,
            () -> converter.toConnectData("topicF5", corrupt));
    String msg = String.valueOf(ex.getMessage());
    // GREEN: the fixed code emits "...record: <class>" (colon). RED: the pre-fix code emitted
    // "...record\n" + e.toString(), so the "record: <class>" form is absent. (Note the ERROR_0010
    // wrapper text itself contains "record\n", so we key the red-green on the "record: " form.)
    assertTrue(
        msg.contains("Failed to parse AVRO record: "),
        "expected sanitized throw message, got: " + msg);
    // And the throw carries no value-bearing cause that a framework stack-trace log could re-leak.
    assertTrue(
        ex.getCause() == null, "sanitized throw must not attach the decode exception as cause");
  }

  /**
   * F5 (log path) — SnowflakeAvroConverter with break-on-error=false: the broken-record ERROR log
   * must carry the decode error class only, not {@code e.getMessage()}.
   */
  @Test
  public void f5_avroWithSchemaRegistry_defaultPath_logsClassNotMessage() throws Exception {
    LogCaptureAppender appender = LogCaptureAppender.attachTo(CONVERTER_LOGGER);
    try {
      MockSchemaRegistryClient client = new MockSchemaRegistryClient();
      SnowflakeAvroConverter converter = new SnowflakeAvroConverter();
      converter.setSchemaRegistry(client);

      byte[] good = client.getData();
      byte[] corrupt = good.clone();
      for (int i = 5; i < corrupt.length; i++) {
        corrupt[i] = (byte) 0xEE;
      }

      SchemaAndValue sv = converter.toConnectData("topicF5b", corrupt);
      assertTrue(((SnowflakeRecordContent) sv.value()).isBroken());

      // GREEN: new format "Failed to parse AVRO record: <class>". RED: old lowercase+newline
      // format.
      assertTrue(
          appender.anyMessageContains("Failed to parse AVRO record: "),
          "expected sanitized ERROR log, got: " + appender.messages());
      assertFalse(
          appender.anyMessageContains("failed to parse AVRO record\n"),
          "log must not use the old message-bearing format: " + appender.messages());
    } finally {
      appender.detach();
    }
  }
}
