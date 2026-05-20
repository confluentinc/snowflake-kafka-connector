package com.snowflake.kafka.connector.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.snowflake.kafka.connector.internal.telemetry.SnowflakeTelemetryService;
import java.util.Collections;
import java.util.List;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.connect.sink.SinkRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SnowflakeSinkServiceV1Test {

  private SnowflakeConnectionService mockConn;
  private SnowflakeSinkServiceV1 sinkService;

  private static final String TEST_TOPIC = "test_topic";
  private static final String TEST_TABLE = "test_table";

  @BeforeEach
  void setup() {
    mockConn = mock(SnowflakeConnectionService.class);
    SnowflakeTelemetryService mockTelemetryService = mock(SnowflakeTelemetryService.class);

    when(mockConn.isClosed()).thenReturn(false);
    when(mockConn.getTelemetryClient()).thenReturn(mockTelemetryService);
    when(mockConn.getConnectorName()).thenReturn(TestUtils.TEST_CONNECTOR_NAME);

    sinkService = new SnowflakeSinkServiceV1(mockConn, 60L);
  }

  @Test
  void enforceTaskBufferLimit_noFlushWhenUnderLimit() {
    // Total buffer across pipes < limit, no flush should occur
    sinkService.configureEnableDynamicFlush(true);
    sinkService.configureTaskBufferLimitBytes(10_000L);

    // Setup table and stage mocks
    setupTableAndStageMocks();

    // Start a partition and insert small records (under limit)
    sinkService.startPartition(TEST_TABLE, new TopicPartition(TEST_TOPIC, 0));

    List<SinkRecord> records = TestUtils.createNativeJsonSinkRecords(0, 1, TEST_TOPIC, 0);
    sinkService.insert(records);

    // Verify buffer is not empty (not flushed due to task buffer limit)
    String pipeName = getNameIndex(TEST_TOPIC, 0);
    assertThat(sinkService.isPartitionBufferEmpty(pipeName)).isFalse();
  }

  @Test
  void enforceTaskBufferLimit_flushWhenOverLimit() {
    // Configure very low limit to force flush
    sinkService.configureEnableDynamicFlush(true);
    sinkService.configureTaskBufferLimitBytes(1L); // Very low limit

    setupTableAndStageMocks();

    sinkService.startPartition(TEST_TABLE, new TopicPartition(TEST_TOPIC, 0));

    List<SinkRecord> records = TestUtils.createNativeJsonSinkRecords(0, 5, TEST_TOPIC, 0);
    sinkService.insert(records);

    // With limit of 1 byte, buffer should be flushed
    String pipeName = getNameIndex(TEST_TOPIC, 0);
    assertThat(sinkService.isPartitionBufferEmpty(pipeName)).isTrue();
  }

  @Test
  void enforceTaskBufferLimit_disabledByDefault() {
    // Dynamic flush is disabled by default
    // Large records should NOT trigger task buffer limit flush
    sinkService.configureTaskBufferLimitBytes(1L); // Low limit but feature disabled

    setupTableAndStageMocks();

    sinkService.startPartition(TEST_TABLE, new TopicPartition(TEST_TOPIC, 0));

    List<SinkRecord> records = TestUtils.createNativeJsonSinkRecords(0, 1, TEST_TOPIC, 0);
    sinkService.insert(records);

    // Buffer should NOT be flushed because dynamic flush is disabled
    String pipeName = getNameIndex(TEST_TOPIC, 0);
    assertThat(sinkService.isPartitionBufferEmpty(pipeName)).isFalse();
  }

  @Test
  void enforceTaskBufferLimit_flushesLargestPipeFirst() {
    sinkService.configureEnableDynamicFlush(true);
    // Set limit low enough that total exceeds after second insert
    // With limit of 500, after second insert the limit is exceeded
    sinkService.configureTaskBufferLimitBytes(500L);

    setupTableAndStageMocks();

    // Start two partitions
    sinkService.startPartition(TEST_TABLE, new TopicPartition(TEST_TOPIC, 0));
    sinkService.startPartition(TEST_TABLE, new TopicPartition(TEST_TOPIC, 1));

    // Insert small records to partition 0 first (under limit)
    List<SinkRecord> smallRecords = TestUtils.createNativeJsonSinkRecords(0, 1, TEST_TOPIC, 0);
    sinkService.insert(smallRecords);

    // Insert more records to partition 1 (making it larger, exceeds limit)
    List<SinkRecord> largeRecords = TestUtils.createNativeJsonSinkRecords(0, 10, TEST_TOPIC, 1);
    sinkService.insert(largeRecords);

    // The larger partition (1) should be flushed first
    String pipe0 = getNameIndex(TEST_TOPIC, 0);
    String pipe1 = getNameIndex(TEST_TOPIC, 1);

    // Verify partition 1 (larger) was flushed, partition 0 was not flushed
    assertThat(sinkService.isPartitionBufferEmpty(pipe1)).isTrue();
    assertThat(sinkService.isPartitionBufferEmpty(pipe0)).isFalse();
  }

  @Test
  void enforceTaskBufferLimit_flushesMultiplePipesIfNeeded() {
    sinkService.configureEnableDynamicFlush(true);
    sinkService.configureTaskBufferLimitBytes(1L); // Force flush all

    setupTableAndStageMocks();

    // Start multiple partitions
    sinkService.startPartition(TEST_TABLE, new TopicPartition(TEST_TOPIC, 0));
    sinkService.startPartition(TEST_TABLE, new TopicPartition(TEST_TOPIC, 1));
    sinkService.startPartition(TEST_TABLE, new TopicPartition(TEST_TOPIC, 2));

    // Insert records to all partitions
    sinkService.insert(TestUtils.createNativeJsonSinkRecords(0, 2, TEST_TOPIC, 0));
    sinkService.insert(TestUtils.createNativeJsonSinkRecords(0, 2, TEST_TOPIC, 1));
    sinkService.insert(TestUtils.createNativeJsonSinkRecords(0, 2, TEST_TOPIC, 2));

    // All pipes should be flushed due to very low limit
    assertThat(sinkService.isPartitionBufferEmpty(getNameIndex(TEST_TOPIC, 0))).isTrue();
    assertThat(sinkService.isPartitionBufferEmpty(getNameIndex(TEST_TOPIC, 1))).isTrue();
    assertThat(sinkService.isPartitionBufferEmpty(getNameIndex(TEST_TOPIC, 2))).isTrue();
  }

  @Test
  void enforceTaskBufferLimit_noPipesIsNoOp() {
    sinkService.configureEnableDynamicFlush(true);
    sinkService.configureTaskBufferLimitBytes(1L);

    // Insert with empty records list - no pipes started
    sinkService.insert(Collections.emptyList());

    // Should not throw, just a no-op
  }

  // Helper method to setup common table and stage mocks
  private void setupTableAndStageMocks() {
    when(mockConn.tableExist(TEST_TABLE)).thenReturn(true);
    when(mockConn.isTableCompatible(TEST_TABLE)).thenReturn(true);
    when(mockConn.stageExist(anyString())).thenReturn(true);
    when(mockConn.isStageCompatible(anyString())).thenReturn(true);
    when(mockConn.listStage(anyString(), anyString())).thenReturn(Collections.emptyList());
    when(mockConn.pipeExist(anyString())).thenReturn(false);
  }

  // Helper method to generate pipe name index (same logic as in SnowflakeSinkServiceV1)
  private String getNameIndex(String topic, int partition) {
    return topic + "_" + partition;
  }
}
