package com.snowflake.kafka.connector.internal;

import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.DescribeTopicsResult;
import org.apache.kafka.clients.admin.TopicDescription;
import org.apache.kafka.common.KafkaFuture;
import org.apache.kafka.common.TopicPartitionInfo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

public class TaskToTopicPartitionValidatorTest {

  @Mock private AdminClient adminClient;
  @Mock private DescribeTopicsResult describeTopicsResult;
  @Mock private KafkaFuture<Map<String, TopicDescription>> kafkaFuture;

  private Map<String, String> config;
  private TaskToTopicPartitionValidator validator;

  @BeforeEach
  public void setUp() {
    MockitoAnnotations.initMocks(this);
    config = new HashMap<>();
    config.put(SnowflakeSinkConnectorConfig.TOPICS, "test-topic");
    config.put(SnowflakeSinkConnectorConfig.BUFFER_SIZE_BYTES, "10000000"); // 10MB
    config.put("tasks.max", "1");

    validator = new TaskToTopicPartitionValidator(config, adminClient);
  }

  @AfterEach
  public void tearDown() {
    validator.stop();
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
    // 51 partitions * 10MB = 510MB > 500MB
    TopicDescription topicDescription =
        new TopicDescription(
            "test-topic", false, Collections.nCopies(60, mock(TopicPartitionInfo.class)));

    Map<String, TopicDescription> descriptions = new HashMap<>();
    descriptions.put("test-topic", topicDescription);

    when(adminClient.describeTopics(anyCollection())).thenReturn(describeTopicsResult);
    when(describeTopicsResult.allTopicNames()).thenReturn(kafkaFuture);
    when(kafkaFuture.get()).thenReturn(descriptions);

    // Execute validation (should log error)
    assertThrows(RuntimeException.class, validator::validateTaskToTopicPartitions);

    // Verify interactions
    verify(adminClient).describeTopics(anyCollection());
  }

  @Test
  public void testValidate_HighUsageWithEnoughTasks() throws Exception {
    // 51 partitions * 10MB = 510MB
    // Increase tasks.max to 2 -> 510MB / 2 = 255MB < 500MB -> OK
    config.put("tasks.max", "2");
    validator = new TaskToTopicPartitionValidator(config, adminClient);

    TopicDescription topicDescription =
        new TopicDescription(
            "test-topic", false, Collections.nCopies(51, mock(TopicPartitionInfo.class)));

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
    validator = new TaskToTopicPartitionValidator(config, adminClient);

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
}

