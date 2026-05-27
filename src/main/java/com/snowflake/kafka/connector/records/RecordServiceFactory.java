package com.snowflake.kafka.connector.records;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig;

public class RecordServiceFactory {

  /**
   * Creates a RecordService with default infinity handling (disabled).
   *
   * @param isIcebergEnabled whether Iceberg mode is enabled
   * @param enableSchematization whether schematization is enabled
   * @return RecordService instance
   */
  public static RecordService createRecordService(
      boolean isIcebergEnabled, boolean enableSchematization) {
    return createRecordService(
        isIcebergEnabled,
        enableSchematization,
        SnowflakeSinkConnectorConfig.ENABLE_STREAMING_INFINITY_HANDLING_DEFAULT);
  }

  /**
   * Creates a RecordService with explicit infinity handling configuration.
   *
   * @param isIcebergEnabled whether Iceberg mode is enabled
   * @param enableSchematization whether schematization is enabled
   * @param enableInfinityHandling whether infinity handling is enabled
   * @return RecordService instance
   */
  public static RecordService createRecordService(
      boolean isIcebergEnabled, boolean enableSchematization, boolean enableInfinityHandling) {
    ObjectMapper objectMapper = new ObjectMapper();
    if (isIcebergEnabled) {
      return new RecordService(
          new IcebergTableStreamingRecordMapper(
              objectMapper, enableSchematization, enableInfinityHandling),
          objectMapper);
    } else {
      return new RecordService(
          new SnowflakeTableStreamingRecordMapper(
              objectMapper, enableSchematization, enableInfinityHandling),
          objectMapper);
    }
  }
}
