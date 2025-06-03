package com.snowflake.kafka.connector.internal;

import com.snowflake.kafka.connector.internal.telemetry.SnowflakeTelemetryService;
import java.security.PrivateKey;
import java.util.Properties;
import javax.annotation.Nullable;

/** A factory to create {@link SnowflakeIngestionService} */
public class SnowflakeIngestionServiceFactory {

  public static SnowflakeIngestionServiceBuilder builder(
      String accountName,
      String userName,
      String host,
      int port,
      String connectionScheme,
      String stageName,
      String pipeName,
      PrivateKey privateKey,
      String userAgentSuffix,
      SnowflakeTelemetryService telemetry) {
    return new SnowflakeIngestionServiceBuilder(
        accountName,
        userName,
        host,
        port,
        connectionScheme,
        stageName,
        pipeName,
        privateKey,
        userAgentSuffix,
        telemetry);
  }

  public static SnowflakeIngestionServiceBuilder builder(
      String accountName,
      String userName,
      String host,
      int port,
      String connectionScheme,
      String stageName,
      String pipeName,
      PrivateKey privateKey,
      String userAgentSuffix,
      SnowflakeTelemetryService telemetry,
      Properties proxyProperties) {
    return new SnowflakeIngestionServiceBuilder(
        accountName,
        userName,
        host,
        port,
        connectionScheme,
        stageName,
        pipeName,
        privateKey,
        userAgentSuffix,
        telemetry,
        proxyProperties);
  }

  /** Builder class to create instance of {@link SnowflakeIngestionService} */
  static class SnowflakeIngestionServiceBuilder {
    private final SnowflakeIngestionService service;

    private SnowflakeIngestionServiceBuilder(
        String accountName,
        String userName,
        String host,
        int port,
        String connectionScheme,
        String stageName,
        String pipeName,
        PrivateKey privateKey,
        String userAgentSuffix,
        @Nullable SnowflakeTelemetryService telemetry) {
      this.service =
          new SnowflakeIngestionServiceV1(
              accountName,
              userName,
              host,
              port,
              connectionScheme,
              stageName,
              pipeName,
              privateKey,
              userAgentSuffix,
              telemetry);
    }

    private SnowflakeIngestionServiceBuilder(
        String accountName,
        String userName,
        String host,
        int port,
        String connectionScheme,
        String stageName,
        String pipeName,
        PrivateKey privateKey,
        String userAgentSuffix,
        @Nullable SnowflakeTelemetryService telemetry,
        Properties proxyProperties) {
      this.service =
          new SnowflakeIngestionServiceV1(
              accountName,
              userName,
              host,
              port,
              connectionScheme,
              stageName,
              pipeName,
              privateKey,
              userAgentSuffix,
              telemetry,
              proxyProperties);
    }

    SnowflakeIngestionServiceBuilder setTelemetry(SnowflakeTelemetryService telemetry) {
      service.setTelemetry(telemetry);
      return this;
    }

    SnowflakeIngestionService build() {
      return service;
    }
  }
}
