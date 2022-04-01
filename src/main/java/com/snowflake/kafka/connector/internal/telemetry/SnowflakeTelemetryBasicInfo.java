package com.snowflake.kafka.connector.internal.telemetry;

import net.snowflake.client.jdbc.internal.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Minimum information needed to sent to Snowflake through Telemetry API */
public abstract class SnowflakeTelemetryBasicInfo {
  final String tableName;
  final String stageName;

  static final Logger LOGGER = LoggerFactory.getLogger(SnowflakeTelemetryBasicInfo.class);

  SnowflakeTelemetryBasicInfo(final String tableName, final String stageName) {
    this.tableName = tableName;
    this.stageName = stageName;
  }

  /**
   * Adds the required fields into the given ObjectNode which will then be used as payload in
   * Telemetry API
   *
   * @param msg ObjectNode in which extra fields needs to be added.
   */
  abstract void dumpTo(ObjectNode msg);

  /**
   * @return true if it would suggest that their was no update to corresponding implementation's
   *     member variables. Or, in other words, the corresponding partition didnt receive any
   *     records, in which case we would not call telemetry API.
   */
  abstract boolean isEmpty();
}
