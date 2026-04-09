package com.snowflake.kafka.connector.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.snowflake.kafka.connector.Utils;
import com.snowflake.kafka.connector.mock.MockResultSetForSizeTest;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import net.snowflake.ingest.connection.IngestStatus;
import org.junit.jupiter.api.Test;

public class InternalUtilsTest {
  @Test
  public void testPrivateKey() {
    assert TestUtils.assertError(
        SnowflakeErrors.ERROR_0002, () -> InternalUtils.parsePrivateKey("adfsfsaff"));

    String key = TestUtils.getKeyString();
    // no exception
    InternalUtils.parsePrivateKey(key);
    StringBuilder builder = new StringBuilder();
    builder.append("-----BEGIN RSA PRIVATE KEY-----\n");
    for (int i = 0; i < key.length(); i++) {
      builder.append(key.charAt(i));
      if ((i + 1) % 64 == 0) {
        builder.append("\n");
      }
    }
    builder.append("\n-----END RSA PRIVATE KEY-----");
    String originalKey = builder.toString();
    // no exception
    InternalUtils.parsePrivateKey(originalKey);
  }

  @Test
  public void testPrivateKeyTooSmall() throws Exception {
    // Generate a 1024-bit RSA key (below the 2048-bit minimum)
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(1024);
    KeyPair keyPair = keyGen.generateKeyPair();
    PrivateKey smallKey = keyPair.getPrivate();
    String smallKeyPem = Base64.getEncoder().encodeToString(smallKey.getEncoded());

    // Should throw ERROR_0033 for key size too small
    SnowflakeKafkaConnectorException exception =
        assertThrows(
            SnowflakeKafkaConnectorException.class,
            () -> InternalUtils.parsePrivateKey(smallKeyPem));
    assertTrue(exception.checkErrorCode(SnowflakeErrors.ERROR_0033));
    assertTrue(
        exception.getMessage().contains("Current key size: 1024 bits, minimum required: 2048"));
  }

  @Test
  public void testValidateRsaKeySize_ValidKey() throws Exception {
    // Generate a 2048-bit RSA key (meets minimum requirement)
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair keyPair = keyGen.generateKeyPair();
    PrivateKey validKey = keyPair.getPrivate();

    // Should not throw any exception
    InternalUtils.validateRsaKeySize(validKey);
  }

  @Test
  public void testIngestStatusConversion() {
    assert InternalUtils.convertIngestStatus(IngestStatus.LOADED)
        == InternalUtils.IngestedFileStatus.LOADED;
    assert InternalUtils.convertIngestStatus(IngestStatus.LOAD_IN_PROGRESS)
        == InternalUtils.IngestedFileStatus.LOAD_IN_PROGRESS;
    assert InternalUtils.convertIngestStatus(IngestStatus.PARTIALLY_LOADED)
        == InternalUtils.IngestedFileStatus.PARTIALLY_LOADED;
    assert InternalUtils.convertIngestStatus(IngestStatus.LOAD_FAILED)
        == InternalUtils.IngestedFileStatus.FAILED;
  }

  @Test
  public void testTimestampToDateConversion() {
    long t = 1563492758649L;
    assert InternalUtils.timestampToDate(t).equals("2019-07-18T23:32:38Z");
  }

  @Test
  public void testAssertNotEmpty() {
    InternalUtils.assertNotEmpty("tableName", "name");
    assert TestUtils.assertError(
        SnowflakeErrors.ERROR_0005, () -> InternalUtils.assertNotEmpty("TABLENAME", null));
    assert TestUtils.assertError(
        SnowflakeErrors.ERROR_0005, () -> InternalUtils.assertNotEmpty("tableName", ""));
    assert TestUtils.assertError(
        SnowflakeErrors.ERROR_0004, () -> InternalUtils.assertNotEmpty("stagename", null));
    assert TestUtils.assertError(
        SnowflakeErrors.ERROR_0004, () -> InternalUtils.assertNotEmpty("stageName", ""));
    assert TestUtils.assertError(
        SnowflakeErrors.ERROR_0006, () -> InternalUtils.assertNotEmpty("pipeName", null));
    assert TestUtils.assertError(
        SnowflakeErrors.ERROR_0006, () -> InternalUtils.assertNotEmpty("pipeName", ""));
    assert TestUtils.assertError(
        SnowflakeErrors.ERROR_0001, () -> InternalUtils.assertNotEmpty("conf", null));
    assert TestUtils.assertError(
        SnowflakeErrors.ERROR_0003, () -> InternalUtils.assertNotEmpty("sfdsfdsfd", null));
    assert TestUtils.assertError(
        SnowflakeErrors.ERROR_0003, () -> InternalUtils.assertNotEmpty("zxcxzcx", ""));
  }

  @Test
  public void testCreateProperties() {
    Map<String, String> config = TestUtils.getConf();
    SnowflakeURL url = TestUtils.getUrl();
    Properties prop = InternalUtils.createProperties(config, 0, 60, url);
    assert prop.containsKey(InternalUtils.JDBC_DATABASE);
    assert prop.containsKey(InternalUtils.JDBC_PRIVATE_KEY);
    assert prop.containsKey(InternalUtils.JDBC_SCHEMA);
    assert prop.containsKey(InternalUtils.JDBC_USER);
    assert prop.containsKey(InternalUtils.JDBC_WAREHOUSE);
    assert prop.containsKey(InternalUtils.JDBC_SESSION_KEEP_ALIVE);
    assert prop.containsKey(InternalUtils.JDBC_SSL);

    assert prop.getProperty(InternalUtils.JDBC_SESSION_KEEP_ALIVE).equals("true");
    if (url.sslEnabled()) {
      assert prop.getProperty(InternalUtils.JDBC_SSL).equals("on");
    } else {
      assert prop.getProperty(InternalUtils.JDBC_SSL).equals("off");
    }

    assert TestUtils.assertError(
        SnowflakeErrors.ERROR_0013,
        () -> {
          Map<String, String> t = new HashMap<>(config);
          t.remove(Utils.SF_PRIVATE_KEY);
          InternalUtils.createProperties(t, 0, 60, url);
        });

    assert TestUtils.assertError(
        SnowflakeErrors.ERROR_0014,
        () -> {
          Map<String, String> t = new HashMap<>(config);
          t.remove(Utils.SF_SCHEMA);
          InternalUtils.createProperties(t, 0, 60, url);
        });

    assert TestUtils.assertError(
        SnowflakeErrors.ERROR_0015,
        () -> {
          Map<String, String> t = new HashMap<>(config);
          t.remove(Utils.SF_DATABASE);
          InternalUtils.createProperties(t, 0, 60, url);
        });

    assert TestUtils.assertError(
        SnowflakeErrors.ERROR_0016,
        () -> {
          Map<String, String> t = new HashMap<>(config);
          t.remove(Utils.SF_USER);
          InternalUtils.createProperties(t, 0, 60, url);
        });
  }

  @Test
  public void testResultSize() throws SQLException {
    ResultSet resultSet = new MockResultSetForSizeTest(0);
    assert InternalUtils.resultSize(resultSet) == 0;
    resultSet = new MockResultSetForSizeTest(100);
    assert InternalUtils.resultSize(resultSet) == 100;
  }

  @Test
  public void parseJdbcPropertiesMapTest() {
    String key = "snowflake.jdbc.map";
    String input =
        "isInsecureMode:true,  disableSamlURLCheck:false, passcodeInPassword:on, foo:bar,"
            + " networkTimeout:100";
    Map<String, String> config = new HashMap<>();
    config.put(key, input);
    // when
    Properties jdbcPropertiesMap = InternalUtils.parseJdbcPropertiesMap(config);
    // then
    assertEquals(jdbcPropertiesMap.size(), 5);
  }

  @Test
  public void parseJdbcPropertiesMapWithOCSPPropertiesTest() {
    String key = "snowflake.jdbc.map";
    String input = "ocspFailOpen:true, disableOCSPChecks:false, ocspResponseCacheSize:1000";
    Map<String, String> config = new HashMap<>();
    config.put(key, input);
    Properties jdbcPropertiesMap = InternalUtils.parseJdbcPropertiesMap(config);
    assertEquals(jdbcPropertiesMap.size(), 3);
    assertEquals("true", jdbcPropertiesMap.getProperty("ocspFailOpen"));
    assertEquals("false", jdbcPropertiesMap.getProperty("disableOCSPChecks"));
    assertEquals("1000", jdbcPropertiesMap.getProperty("ocspResponseCacheSize"));
  }

  @Test
  public void parseJdbcPropertiesMapWithDisableOCSPChecksConfigTest() {
    Map<String, String> config = new HashMap<>();
    config.put(
        com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.SNOWFLAKE_DISABLE_OCSP_CHECKS,
        "true");
    Properties jdbcPropertiesMap = InternalUtils.parseJdbcPropertiesMap(config);
    assertEquals("true", jdbcPropertiesMap.getProperty("disableOCSPChecks"));
  }

  @Test
  public void parseJdbcPropertiesMapWithDisableOCSPChecksConfigFalseTest() {
    Map<String, String> config = new HashMap<>();
    config.put(
        com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.SNOWFLAKE_DISABLE_OCSP_CHECKS,
        "false");
    Properties jdbcPropertiesMap = InternalUtils.parseJdbcPropertiesMap(config);
    assertEquals(0, jdbcPropertiesMap.size());
    assertEquals(null, jdbcPropertiesMap.getProperty("disableOCSPChecks"));
  }

  @Test
  public void parseJdbcPropertiesMapWithOCSPConflictTest() {
    // explicit config should override jdbc.map when both are set
    String key = "snowflake.jdbc.map";
    String input = "disableOCSPChecks:false, ocspFailOpen:true";
    Map<String, String> config = new HashMap<>();
    config.put(key, input);
    config.put(
        com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.SNOWFLAKE_DISABLE_OCSP_CHECKS,
        "true");
    Properties jdbcPropertiesMap = InternalUtils.parseJdbcPropertiesMap(config);
    // explicit config overrides disableOCSPChecks, but ocspFailOpen from jdbc.map is preserved
    assertEquals("true", jdbcPropertiesMap.getProperty("disableOCSPChecks"));
    assertEquals("true", jdbcPropertiesMap.getProperty("ocspFailOpen"));
  }
}
