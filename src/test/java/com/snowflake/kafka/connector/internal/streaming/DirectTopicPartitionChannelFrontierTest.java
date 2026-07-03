package com.snowflake.kafka.connector.internal.streaming;

import static com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.ENABLE_METADATA_FLOOR_RECOVERY;
import static com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.ENABLE_NULL_RECORD_OFFSET_ADVANCE;
import static com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.ERRORS_DEAD_LETTER_QUEUE_TOPIC_NAME_CONFIG;
import static com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.ERRORS_TOLERANCE_CONFIG;
import static com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.METADATA_FLOOR_GROUP_ID;
import static com.snowflake.kafka.connector.internal.streaming.channel.TopicPartitionChannel.NO_OFFSET_TOKEN_REGISTERED_IN_SNOWFLAKE;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;

import com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig;
import com.snowflake.kafka.connector.dlq.InMemoryKafkaRecordErrorReporter;
import com.snowflake.kafka.connector.dlq.KafkaRecordErrorReporter;
import com.snowflake.kafka.connector.internal.SnowflakeConnectionService;
import com.snowflake.kafka.connector.internal.TestUtils;
import com.snowflake.kafka.connector.internal.streaming.schemaevolution.InsertErrorMapper;
import com.snowflake.kafka.connector.internal.streaming.schemaevolution.SchemaEvolutionService;
import com.snowflake.kafka.connector.internal.telemetry.SnowflakeTelemetryService;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import net.snowflake.ingest.streaming.InsertValidationResponse;
import net.snowflake.ingest.streaming.OpenChannelRequest;
import net.snowflake.ingest.streaming.SnowflakeStreamingIngestChannel;
import net.snowflake.ingest.streaming.SnowflakeStreamingIngestClient;
import net.snowflake.ingest.utils.ErrorCode;
import net.snowflake.ingest.utils.SFException;
import org.apache.kafka.clients.consumer.OffsetAndMetadata;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.connect.sink.SinkRecord;
import org.apache.kafka.connect.sink.SinkTaskContext;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

/**
 * Unit tests for the decided-frontier pending-set lifecycle (entry at receipt, prune at durable
 * token, removal on decided drop, retention across channel reset, cap at the consumed position) and
 * for the metadata-floor recovery seek in the constructor.
 */
public class DirectTopicPartitionChannelFrontierTest {

  private static final String TOPIC = "TEST";
  private static final int PARTITION = 0;
  private static final String TEST_TABLE_NAME = "TEST_TABLE";

  private SnowflakeStreamingIngestClient mockStreamingClient;
  private SnowflakeStreamingIngestChannel mockStreamingChannel;
  private KafkaRecordErrorReporter mockKafkaRecordErrorReporter;
  private SinkTaskContext mockSinkTaskContext;
  private SnowflakeConnectionService mockSnowflakeConnectionService;
  private SnowflakeTelemetryService mockTelemetryService;
  private SchemaEvolutionService mockSchemaEvolutionService;

  private TopicPartition topicPartition;
  private String testChannelName;
  private Map<String, String> sfConnectorConfig;

  // Durable-token holder so tests can move the token between calls without re-stubbing.
  private final AtomicReference<String> durableToken = new AtomicReference<>(null);

  private static final SFException SF_EXCEPTION =
      new SFException(ErrorCode.INVALID_CHANNEL, "INVALID_CHANNEL");

  @Before
  public void setup() {
    mockStreamingClient = Mockito.mock(SnowflakeStreamingIngestClient.class);
    mockStreamingChannel = Mockito.mock(SnowflakeStreamingIngestChannel.class);
    mockKafkaRecordErrorReporter = Mockito.mock(KafkaRecordErrorReporter.class);
    mockSinkTaskContext = Mockito.mock(SinkTaskContext.class);
    mockSnowflakeConnectionService = Mockito.mock(SnowflakeConnectionService.class);
    mockTelemetryService = Mockito.mock(SnowflakeTelemetryService.class);
    mockSchemaEvolutionService = Mockito.mock(SchemaEvolutionService.class);

    Mockito.when(mockStreamingClient.isClosed()).thenReturn(false);
    Mockito.when(mockStreamingClient.openChannel(ArgumentMatchers.any(OpenChannelRequest.class)))
        .thenReturn(mockStreamingChannel);
    durableToken.set(null);
    Mockito.when(mockStreamingChannel.getLatestCommittedOffsetToken())
        .thenAnswer(invocation -> durableToken.get());

    topicPartition = new TopicPartition(TOPIC, PARTITION);
    testChannelName = SnowflakeSinkServiceV2.partitionChannelKey(null, TOPIC, PARTITION);
    Mockito.when(mockStreamingChannel.getFullyQualifiedName()).thenReturn(testChannelName);

    sfConnectorConfig = TestUtils.getConfig();
    sfConnectorConfig.put(ENABLE_NULL_RECORD_OFFSET_ADVANCE, "true");
  }

  private DirectTopicPartitionChannel createChannel() {
    return createChannel(mockKafkaRecordErrorReporter);
  }

  private DirectTopicPartitionChannel createChannel(KafkaRecordErrorReporter errorReporter) {
    return new DirectTopicPartitionChannel(
        mockStreamingClient,
        topicPartition,
        testChannelName,
        TEST_TABLE_NAME,
        sfConnectorConfig,
        errorReporter,
        mockSinkTaskContext,
        mockSnowflakeConnectionService,
        mockTelemetryService,
        mockSchemaEvolutionService,
        new InsertErrorMapper());
  }

  private void stubCleanInserts() {
    Mockito.when(mockStreamingChannel.insertRow(anyMap(), anyString()))
        .thenReturn(new InsertValidationResponse());
  }

  private List<SinkRecord> records(int startOffset, int count) throws Exception {
    return TestUtils.createJsonStringSinkRecords(startOffset, count, TOPIC, PARTITION);
  }

  @Test
  public void testGetDecidedFrontier_featureOff_returnsSentinel() throws Exception {
    sfConnectorConfig.remove(ENABLE_NULL_RECORD_OFFSET_ADVANCE);
    stubCleanInserts();
    DirectTopicPartitionChannel channel = createChannel();

    List<SinkRecord> batch = records(0, 3);
    for (int idx = 0; idx < batch.size(); idx++) {
      channel.insertRecord(batch.get(idx), idx == 0);
    }

    Assert.assertEquals(NO_OFFSET_TOKEN_REGISTERED_IN_SNOWFLAKE, channel.getDecidedFrontier(42L));
  }

  @Test
  public void testGetDecidedFrontier_nothingPending_returnsConsumedHwm() {
    DirectTopicPartitionChannel channel = createChannel();

    Assert.assertEquals(42L, channel.getDecidedFrontier(42L));
  }

  @Test
  public void testPendingSet_entryAtReceipt_boundsFrontier() throws Exception {
    stubCleanInserts();
    DirectTopicPartitionChannel channel = createChannel();

    List<SinkRecord> batch = records(0, 5);
    for (int idx = 0; idx < batch.size(); idx++) {
      channel.insertRecord(batch.get(idx), idx == 0);
    }

    // Nothing durable yet, so the lowest received record bounds the frontier.
    Assert.assertEquals(0L, channel.getDecidedFrontier(10L));
  }

  @Test
  public void testPendingSet_prunedByDurableToken() throws Exception {
    stubCleanInserts();
    DirectTopicPartitionChannel channel = createChannel();

    List<SinkRecord> batch = records(0, 5);
    for (int idx = 0; idx < batch.size(); idx++) {
      channel.insertRecord(batch.get(idx), idx == 0);
    }

    durableToken.set("2");
    Assert.assertEquals(3L, channel.getDecidedFrontier(10L));

    durableToken.set("4");
    Assert.assertEquals(10L, channel.getDecidedFrontier(10L));
  }

  @Test
  public void testGetDecidedFrontier_cappedAtConsumedHwm() throws Exception {
    stubCleanInserts();
    DirectTopicPartitionChannel channel = createChannel();

    List<SinkRecord> batch = records(3, 2);
    for (int idx = 0; idx < batch.size(); idx++) {
      channel.insertRecord(batch.get(idx), idx == 0);
    }

    // Pending is {3, 4} but the consumed position sits below it, e.g. after a rewind.
    Assert.assertEquals(1L, channel.getDecidedFrontier(1L));
  }

  @Test
  public void testPendingSet_decidedDropRemoval_deadLetteredRecord() throws Exception {
    InsertValidationResponse errorResponse = new InsertValidationResponse();
    InsertValidationResponse.InsertError insertError =
        new InsertValidationResponse.InsertError("CONTENT", 0);
    insertError.setException(SF_EXCEPTION);
    errorResponse.addError(insertError);
    Mockito.when(mockStreamingChannel.insertRow(anyMap(), anyString())).thenReturn(errorResponse);

    sfConnectorConfig.put(
        ERRORS_TOLERANCE_CONFIG, SnowflakeSinkConnectorConfig.ErrorTolerance.ALL.toString());
    sfConnectorConfig.put(ERRORS_DEAD_LETTER_QUEUE_TOPIC_NAME_CONFIG, "dlq_topic");

    InMemoryKafkaRecordErrorReporter errorReporter = new InMemoryKafkaRecordErrorReporter();
    DirectTopicPartitionChannel channel = createChannel(errorReporter);

    channel.insertRecord(records(0, 1).get(0), true);

    // The record was dead-lettered, so it is decided and no longer bounds the frontier.
    Assert.assertEquals(1, errorReporter.getReportedRecords().size());
    Assert.assertEquals(5L, channel.getDecidedFrontier(5L));
  }

  @Test
  public void testPendingSet_retainedAcrossChannelReset() throws Exception {
    Mockito.when(mockStreamingChannel.insertRow(anyMap(), eq("0")))
        .thenReturn(new InsertValidationResponse());
    Mockito.when(mockStreamingChannel.insertRow(anyMap(), eq("1"))).thenThrow(SF_EXCEPTION);

    DirectTopicPartitionChannel channel = createChannel();

    List<SinkRecord> batch = records(0, 3);
    channel.insertRecord(batch.get(0), true);

    // Record 0 becomes durable; record 1 fails the insert, which resets the channel and requests
    // a re-seek to 1.
    durableToken.set("0");
    channel.insertRecord(batch.get(1), false);
    Mockito.verify(mockSinkTaskContext).offset(topicPartition, 1L);

    // Record 1 is discarded but still undecided, so it must keep bounding the frontier inside the
    // window between the reset and the rewind.
    Assert.assertEquals(1L, channel.getDecidedFrontier(2L));

    // Leftover batch records are skipped while the re-seek is pending, but stay tracked.
    channel.insertRecord(batch.get(2), false);
    Assert.assertEquals(1L, channel.getDecidedFrontier(3L));
  }

  /**
   * Overrides the broker read so floor-recovery tests can run without an AdminClient. A static
   * holder is used because the base constructor invokes the override before instance fields of this
   * subclass are initialized.
   */
  private static class FloorStubbedChannel extends DirectTopicPartitionChannel {
    private static Callable<OffsetAndMetadata> committedStub;

    FloorStubbedChannel(
        SnowflakeStreamingIngestClient streamingIngestClient,
        TopicPartition topicPartition,
        String channelName,
        String tableName,
        Map<String, String> sfConnectorConfig,
        KafkaRecordErrorReporter kafkaRecordErrorReporter,
        SinkTaskContext sinkTaskContext,
        SnowflakeConnectionService conn,
        SnowflakeTelemetryService telemetryService,
        SchemaEvolutionService schemaEvolutionService) {
      super(
          streamingIngestClient,
          topicPartition,
          channelName,
          tableName,
          sfConnectorConfig,
          kafkaRecordErrorReporter,
          sinkTaskContext,
          conn,
          telemetryService,
          schemaEvolutionService,
          new InsertErrorMapper());
    }

    @Override
    OffsetAndMetadata fetchCommittedOffsetAndMetadata(String groupId) throws Exception {
      return committedStub.call();
    }
  }

  private FloorStubbedChannel createFloorChannel(Callable<OffsetAndMetadata> committedStub) {
    FloorStubbedChannel.committedStub = committedStub;
    return new FloorStubbedChannel(
        mockStreamingClient,
        topicPartition,
        testChannelName,
        TEST_TABLE_NAME,
        sfConnectorConfig,
        mockKafkaRecordErrorReporter,
        mockSinkTaskContext,
        mockSnowflakeConnectionService,
        mockTelemetryService,
        mockSchemaEvolutionService);
  }

  private void enableFloorRecovery() {
    sfConnectorConfig.put(ENABLE_METADATA_FLOOR_RECOVERY, "true");
    sfConnectorConfig.put(METADATA_FLOOR_GROUP_ID, "connect-test-connector");
  }

  @Test
  public void testFloorRecovery_consistentFloorAboveToken_seeksToFloorPlusOne() {
    enableFloorRecovery();
    durableToken.set("4");
    createFloorChannel(() -> new OffsetAndMetadata(10L, "floor=9"));

    Mockito.verify(mockSinkTaskContext).offset(topicPartition, 10L);
  }

  @Test
  public void testFloorRecovery_tokenNull_seeksToFloorPlusOne() {
    enableFloorRecovery();
    durableToken.set(null);
    createFloorChannel(() -> new OffsetAndMetadata(10L, "floor=9"));

    Mockito.verify(mockSinkTaskContext).offset(topicPartition, 10L);
  }

  @Test
  public void testFloorRecovery_floorBelowToken_seeksToTokenPlusOne() {
    enableFloorRecovery();
    durableToken.set("9");
    createFloorChannel(() -> new OffsetAndMetadata(5L, "floor=4"));

    Mockito.verify(mockSinkTaskContext).offset(topicPartition, 10L);
  }

  @Test
  public void testFloorRecovery_inconsistentFloor_ignored() {
    enableFloorRecovery();
    durableToken.set("4");
    // Every commit this connector writes satisfies floor == committedOffset - 1, so this floor was
    // written by something else and must not be honored.
    createFloorChannel(() -> new OffsetAndMetadata(10L, "floor=5"));

    Mockito.verify(mockSinkTaskContext).offset(topicPartition, 5L);
  }

  @Test
  public void testFloorRecovery_noFloorInMetadata_seeksToTokenPlusOne() {
    enableFloorRecovery();
    durableToken.set("4");
    createFloorChannel(() -> new OffsetAndMetadata(10L, ""));

    Mockito.verify(mockSinkTaskContext).offset(topicPartition, 5L);
  }

  @Test
  public void testFloorRecovery_readFailure_seeksToTokenPlusOne() {
    enableFloorRecovery();
    durableToken.set("4");
    createFloorChannel(
        () -> {
          throw new RuntimeException("broker unavailable");
        });

    Mockito.verify(mockSinkTaskContext).offset(topicPartition, 5L);
  }

  @Test
  public void testFloorRecovery_missingGroupId_skipsReadAndSeeksToTokenPlusOne() {
    sfConnectorConfig.put(ENABLE_METADATA_FLOOR_RECOVERY, "true");
    durableToken.set("4");
    // AssertionError is not caught by the floor read's exception handling, so a read attempt
    // would fail the test.
    createFloorChannel(
        () -> {
          throw new AssertionError("floor read should be skipped without a group id");
        });

    Mockito.verify(mockSinkTaskContext).offset(topicPartition, 5L);
  }
}
