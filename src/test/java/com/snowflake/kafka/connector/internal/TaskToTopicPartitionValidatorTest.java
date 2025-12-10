package com.snowflake.kafka.connector.internal;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.DescribeTopicsResult;
import org.apache.kafka.clients.admin.TopicDescription;
import org.apache.kafka.common.KafkaFuture;
import org.apache.kafka.common.TopicPartitionInfo;
import org.apache.kafka.connect.connector.ConnectorContext;
import org.apache.kafka.connect.errors.ConnectException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;

public class TaskToTopicPartitionValidatorTest {

  private static final long DEFAULT_VALIDATION_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

  @Mock private AdminClient adminClient;
  @Mock private DescribeTopicsResult describeTopicsResult;
  @Mock private KafkaFuture<Map<String, TopicDescription>> kafkaFuture;
  @Mock private ConnectorContext connectorContext;

  private Map<String, String> config;
  private TaskToTopicPartitionValidator validator;

  @BeforeEach
  public void setUp() {
    MockitoAnnotations.initMocks(this);
    config = new HashMap<>();
    config.put(SnowflakeSinkConnectorConfig.TOPICS, "test-topic");
    config.put(SnowflakeSinkConnectorConfig.BUFFER_SIZE_BYTES, "10000000"); // 10MB
    config.put("tasks.max", "1");

    validator =
        new TaskToTopicPartitionValidator(
            config, connectorContext, adminClient, DEFAULT_VALIDATION_INTERVAL_MS);
  }

  @AfterEach
  public void tearDown() {
    validator.shutdown();
  }

  @Test
  public void testValidate_HappyPath() throws Exception {
    // Mock AdminClient behavior
    TopicDescription topicDescription =
        new TopicDescription(
            "test-topic",
            false,
            Collections.singletonList(
                new TopicPartitionInfo(0, null, Collections.emptyList(), Collections.emptyList())));

    Map<String, TopicDescription> descriptions = new HashMap<>();
    descriptions.put("test-topic", topicDescription);

    when(adminClient.describeTopics(anyCollection())).thenReturn(describeTopicsResult);
    when(describeTopicsResult.allTopicNames()).thenReturn(kafkaFuture);
    when(kafkaFuture.get()).thenReturn(descriptions);

    // Execute validation (should not log error)
    validator.validateTaskToTopicPartitions();

    // Verify interactions
    verify(adminClient).describeTopics(anyCollection());
  }

  @Test
  public void testValidate_HighUsage() throws Exception {
    // Increase partitions to exceed 500MB with 10MB buffer size (requires > 50 partitions)
    // 60 partitions * 10MB = 600MB > 500MB
    TopicDescription topicDescription =
        new TopicDescription(
            "test-topic", false, Collections.nCopies(60, mock(TopicPartitionInfo.class)));

    Map<String, TopicDescription> descriptions = new HashMap<>();
    descriptions.put("test-topic", topicDescription);

    when(adminClient.describeTopics(anyCollection())).thenReturn(describeTopicsResult);
    when(describeTopicsResult.allTopicNames()).thenReturn(kafkaFuture);
    when(kafkaFuture.get()).thenReturn(descriptions);

    // Execute validation (should log error)
    assertThrows(ConnectException.class, validator::validateTaskToTopicPartitions);

    // Verify interactions
    verify(adminClient).describeTopics(anyCollection());
  }

  @Test
  public void testValidate_HighUsageWithEnoughTasks() throws Exception {
    // 60 partitions * 10MB = 600MB > 500MB
    config.put("tasks.max", "2");
    validator =
        new TaskToTopicPartitionValidator(
            config, connectorContext, adminClient, DEFAULT_VALIDATION_INTERVAL_MS);

    TopicDescription topicDescription =
        new TopicDescription(
            "test-topic", false, Collections.nCopies(60, mock(TopicPartitionInfo.class)));

    Map<String, TopicDescription> descriptions = new HashMap<>();
    descriptions.put("test-topic", topicDescription);

    when(adminClient.describeTopics(anyCollection())).thenReturn(describeTopicsResult);
    when(describeTopicsResult.allTopicNames()).thenReturn(kafkaFuture);
    when(kafkaFuture.get()).thenReturn(descriptions);

    // Execute validation
    validator.validateTaskToTopicPartitions();

    // Verify interactions
    verify(adminClient).describeTopics(anyCollection());
  }

  @Test
  public void testValidate_InvalidConfig() throws Exception {
    config.put("tasks.max", "invalid");
    validator =
        new TaskToTopicPartitionValidator(
            config, connectorContext, adminClient, DEFAULT_VALIDATION_INTERVAL_MS);

    TopicDescription topicDescription =
        new TopicDescription(
            "test-topic",
            false,
            Collections.singletonList(
                new TopicPartitionInfo(0, null, Collections.emptyList(), Collections.emptyList())));

    Map<String, TopicDescription> descriptions = new HashMap<>();
    descriptions.put("test-topic", topicDescription);

    when(adminClient.describeTopics(anyCollection())).thenReturn(describeTopicsResult);
    when(describeTopicsResult.allTopicNames()).thenReturn(kafkaFuture);
    when(kafkaFuture.get()).thenReturn(descriptions);

    // Execute validation (should fall back to defaults and proceed)
    validator.validateTaskToTopicPartitions();

    verify(adminClient).describeTopics(anyCollection());
  }

  /**
   * Test the requiredTasks calculation formula:
   * requiredTasks = (totalPartitions * bufferSizeBytes + MEMORY_LIMIT_BYTES - 1) / MEMORY_LIMIT_BYTES
   *
   * This is a ceiling division that calculates the minimum number of tasks needed
   * to keep per-task memory usage under 500MB.
   *
   * Examples:
   * - 100 partitions * 10MB = 1000MB, requiredTasks = ceil(1000/500) = 2
   * - 150 partitions * 10MB = 1500MB, requiredTasks = ceil(1500/500) = 3
   * - 51 partitions * 10MB = 510MB, requiredTasks = ceil(510/500) = 2
   * - 500 partitions * 10MB = 5000MB, requiredTasks = ceil(5000/500) = 10
   */
  @ParameterizedTest
  @CsvSource({
      "100, 10000000, 2",   // 100 partitions * 10MB = 1000MB -> ceil(1000/500) = 2
      "150, 10000000, 3",   // 150 partitions * 10MB = 1500MB -> ceil(1500/500) = 3
      "51, 10000000, 2",    // 51 partitions * 10MB = 510MB -> ceil(510/500) = 2 (just over limit)
      "500, 10000000, 10",  // 500 partitions * 10MB = 5000MB -> ceil(5000/500) = 10
      "100, 50000000, 10",  // 100 partitions * 50MB = 5000MB -> ceil(5000/500) = 10
      "50, 10000000, 1",    // 50 partitions * 10MB = 500MB -> ceil(500/500) = 1 (exactly at limit)
  })
  public void testRequiredTasksCalculation(int partitions, long bufferSize, long expectedRequiredTasks)
      throws Exception {
    // Setup config with specified buffer size
    config.put(SnowflakeSinkConnectorConfig.BUFFER_SIZE_BYTES, String.valueOf(bufferSize));
    config.put("tasks.max", "1");
    validator =
        new TaskToTopicPartitionValidator(
            config, connectorContext, adminClient, DEFAULT_VALIDATION_INTERVAL_MS);

    // Create topic description with specified partition count
    TopicDescription topicDescription =
        new TopicDescription(
            "test-topic", false, Collections.nCopies(partitions, mock(TopicPartitionInfo.class)));

    Map<String, TopicDescription> descriptions = new HashMap<>();
    descriptions.put("test-topic", topicDescription);

    when(adminClient.describeTopics(anyCollection())).thenReturn(describeTopicsResult);
    when(describeTopicsResult.allTopicNames()).thenReturn(kafkaFuture);
    when(kafkaFuture.get()).thenReturn(descriptions);

    // Calculate expected memory usage
    long expectedMemoryUsage = partitions * bufferSize;
    long memoryLimit = 500 * 1024 * 1024; // 500MB

    if (expectedMemoryUsage > memoryLimit) {
      // Should throw exception with correct requiredTasks in message
      ConnectException exception =
          assertThrows(ConnectException.class, validator::validateTaskToTopicPartitions);

      String expectedMessage = "tasks.max to at least " + expectedRequiredTasks;
      assertTrue(
          "Exception message should contain 'tasks.max to at least " + expectedRequiredTasks + "' but was: "
              + exception.getMessage(),
          exception.getMessage().contains(expectedMessage));
    } else {
      // Should pass without exception
      validator.validateTaskToTopicPartitions();
    }

    verify(adminClient).describeTopics(anyCollection());
  }

  /**
   * Test the full thread lifecycle where partition count increases mid-run and fails the connector.
   *
   * <p>Scenario:
   * 1. Thread starts with a short validation interval (500ms)
   * 2. First validation call returns 10 partitions (passes - 10 * 10MB = 100MB < 500MB)
   * 3. Second validation call returns 100 partitions (fails - 100 * 10MB = 1000MB > 500MB)
   * 4. Verify context.raiseError() is called
   */
  @Test
  public void testThreadLifecycle_PartitionCountIncreases_FailsConnector() throws Exception {
    // Use a short validation interval for testing (500ms)
    long shortIntervalMs = 500;
    validator =
        new TaskToTopicPartitionValidator(config, connectorContext, adminClient, shortIntervalMs);

    // Track how many times describeTopics is called
    AtomicInteger callCount = new AtomicInteger(0);

    // Create topic descriptions - first call has few partitions, second has many
    TopicDescription fewPartitions =
        new TopicDescription(
            "test-topic", false, Collections.nCopies(10, mock(TopicPartitionInfo.class)));
    TopicDescription manyPartitions =
        new TopicDescription(
            "test-topic", false, Collections.nCopies(100, mock(TopicPartitionInfo.class)));

    // Setup mock to return different partition counts on successive calls
    when(adminClient.describeTopics(anyCollection())).thenReturn(describeTopicsResult);
    when(describeTopicsResult.allTopicNames()).thenReturn(kafkaFuture);
    when(kafkaFuture.get())
        .thenAnswer(
            (InvocationOnMock invocation) -> {
              int count = callCount.incrementAndGet();
              Map<String, TopicDescription> descriptions = new HashMap<>();
              if (count == 1) {
                // First call: few partitions (passes)
                descriptions.put("test-topic", fewPartitions);
              } else {
                // Second call: many partitions (fails)
                descriptions.put("test-topic", manyPartitions);
              }
              return descriptions;
            });

    // Start the validator thread
    validator.start();

    // Wait for context.raiseError to be called (with timeout)
    // The thread should:
    // 1. Run first validation (pass)
    // 2. Wait 500ms
    // 3. Run second validation (fail)
    // 4. Call context.raiseError()
    verify(connectorContext, timeout(3000)).raiseError(any(ConnectException.class));

    // Verify that describeTopics was called at least twice
    verify(adminClient, atLeast(2)).describeTopics(anyCollection());

    // The thread should have stopped itself after failing
    // Give it a moment to fully stop
    Thread.sleep(100);
    Assertions.assertFalse(validator.isAlive(), "Validator thread should not be alive after failure");
  }
}

