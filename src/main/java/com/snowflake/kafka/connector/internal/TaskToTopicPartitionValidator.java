package com.snowflake.kafka.connector.internal;

import static com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.BUFFER_SIZE_BYTES;
import static com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.BUFFER_SIZE_BYTES_DEFAULT;
import static com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.ENABLE_DYNAMIC_FLUSH;
import static com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.ENABLE_DYNAMIC_FLUSH_DEFAULT;
import static com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.TASK_TO_TOPIC_PARTITIONS_VALIDATION_FAILURE_ACTION;
import static com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.TASK_TO_TOPIC_PARTITIONS_VALIDATION_FAILURE_ACTION_DEFAULT;
import static com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.TASK_TO_TOPIC_PARTITIONS_VALIDATION_INTERVAL_MS;
import static com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.TASK_TO_TOPIC_PARTITIONS_VALIDATION_INTERVAL_MS_DEFAULT;
import static com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.TASK_TO_TOPIC_PARTITIONS_VALIDATION_MEMORY_LIMIT_IN_BYTES;
import static com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.TASK_TO_TOPIC_PARTITIONS_VALIDATION_MEMORY_LIMIT_IN_BYTES_DEFAULT;

import com.google.common.annotations.VisibleForTesting;
import com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig;
import com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.TaskToTopicPartitionValidatorFailureAction;
import com.snowflake.kafka.connector.Utils;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.DescribeTopicsResult;
import org.apache.kafka.clients.admin.TopicDescription;
import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.errors.UnknownTopicOrPartitionException;
import org.apache.kafka.connect.errors.ConnectException;

/**
 * Thread that periodically validates that the total memory usage (partitions * buffer size) does
 * not exceed a safety threshold.
 *
 * <p>This class handles its own Kafka AdminClient lifecycle for checking partition counts.
 */
public class TaskToTopicPartitionValidator extends Thread {
  private static final KCLogger LOGGER =
      new KCLogger(TaskToTopicPartitionValidator.class.getName());
  private final Map<String, String> config;
  private final AtomicReference<Throwable> failure;
  private final CountDownLatch shutdownLatch;
  private final long validationIntervalMs;
  private final int maxTopicPartitionsPerTask;
  private final boolean enableDynamicFlush;
  private final TaskToTopicPartitionValidatorFailureAction failureAction;
  private AdminClient adminClient;
  private final int RELAXED_MULTIPLIER = 2;

  public TaskToTopicPartitionValidator(
      Map<String, String> config, AtomicReference<Throwable> failure, String taskConfigId) {
    this(config, null, failure, taskConfigId);
  }

  // Constructor for testing with custom interval
  public TaskToTopicPartitionValidator(
      Map<String, String> config,
      AdminClient adminClient,
      AtomicReference<Throwable> failure,
      String taskConfigId) {
    this.config = config;
    this.adminClient = adminClient;
    this.validationIntervalMs =
        Long.parseLong(
            config.getOrDefault(
                TASK_TO_TOPIC_PARTITIONS_VALIDATION_INTERVAL_MS,
                String.valueOf(TASK_TO_TOPIC_PARTITIONS_VALIDATION_INTERVAL_MS_DEFAULT)));
    long baseMemoryLimitBytes =
        Long.parseLong(
            config.getOrDefault(
                TASK_TO_TOPIC_PARTITIONS_VALIDATION_MEMORY_LIMIT_IN_BYTES,
                String.valueOf(TASK_TO_TOPIC_PARTITIONS_VALIDATION_MEMORY_LIMIT_IN_BYTES_DEFAULT)));
    long bufferSizeBytes =
        Long.parseLong(
            config.getOrDefault(BUFFER_SIZE_BYTES, String.valueOf(BUFFER_SIZE_BYTES_DEFAULT)));
    int baseMaxTopicPartitionsPerTask = (int) (baseMemoryLimitBytes / bufferSizeBytes);
    this.enableDynamicFlush =
        Boolean.parseBoolean(
            config.getOrDefault(
                ENABLE_DYNAMIC_FLUSH, String.valueOf(ENABLE_DYNAMIC_FLUSH_DEFAULT)));
    // If dynamic flush is enabled, we allow up to 2x topic partitions
    this.maxTopicPartitionsPerTask =
        enableDynamicFlush
            ? baseMaxTopicPartitionsPerTask * RELAXED_MULTIPLIER
            : baseMaxTopicPartitionsPerTask;
    String failureActionStr =
        config.getOrDefault(
            TASK_TO_TOPIC_PARTITIONS_VALIDATION_FAILURE_ACTION,
            TASK_TO_TOPIC_PARTITIONS_VALIDATION_FAILURE_ACTION_DEFAULT);
    this.failureAction =
        TaskToTopicPartitionValidatorFailureAction.valueOf(failureActionStr.toUpperCase());
    this.shutdownLatch = new CountDownLatch(1);
    this.setName(
        config.get(Utils.NAME) + "-" + taskConfigId + "-task-to-topic-partitions-validator");
    this.failure = failure;
  }

  @Override
  public void run() {
    LOGGER.info("Starting TaskToTopicPartitionValidator thread.");
    // Initialize AdminClient if not provided
    if (this.adminClient == null) {
      try {
        initializeAdminClient();
      } catch (Exception e) {
        fail(e, "Error while initializing AdminClient for TaskToTopicPartitionValidator");
      }
    }
    try {
      while (true) {
        try {
          validateTaskToTopicPartitions();
        } catch (ConnectException e) {
          fail(e, "Error while running TaskToTopicPartition validation");
        }
        try {
          long jitterMs = ThreadLocalRandom.current().nextLong(0, 5000);
          LOGGER.debug(
              "Waiting {} ms to check for buffer size validation.",
              validationIntervalMs + jitterMs);
          boolean shuttingDown =
              shutdownLatch.await(validationIntervalMs + jitterMs, TimeUnit.MILLISECONDS);
          if (shuttingDown) {
            return;
          }
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          LOGGER.info("Validator thread interrupted, shutting down");
          return;
        }
      }
    } finally {
      closeAdminClient();
    }
  }

  public void shutdown() {
    LOGGER.info("Shutting down TaskToTopicPartitionValidator thread.");
    shutdownLatch.countDown();
  }

  /**
   * Run initial validation synchronously before starting the thread. This method should be called
   * before start() to fail fast if validation fails.
   *
   * @throws ConnectException if validation fails and failure action is set to FAIL.
   */
  public void runInitialValidation() {
    LOGGER.info("Running initial TaskToTopicPartition validation...");
    try {
      if (this.adminClient == null) {
        initializeAdminClient();
      }
      validateTaskToTopicPartitions();
      LOGGER.info("Initial TaskToTopicPartition validation passed.");
    } catch (Exception e) {
      closeAdminClient();
      fail(e, "Error while running initial TaskToTopicPartition validation.");
    }
  }

  private void initializeAdminClient() {
    Properties props = new Properties();
    if (config != null) {
      // Handle admin.override.* properties
      for (Map.Entry<String, String> entry : config.entrySet()) {
        String key = entry.getKey();
        if (key.startsWith("admin.override.")) {
          // Strip the prefix and use the rest of the key
          props.put(key.substring("admin.override.".length()), entry.getValue());
        }
      }
    }
    LOGGER.info("Initializing Kafka Admin Client for Validator");
    try {
      this.adminClient = AdminClient.create(props);
    } catch (Exception e) {
      LOGGER.error("Failed to create Kafka Admin Client: {}", e.getMessage());
      throw new KafkaException(e);
    }
  }

  private void closeAdminClient() {
    if (adminClient != null) {
      LOGGER.info("Closing Kafka Admin Client");
      try {
        adminClient.close();
      } catch (Exception e) {
        LOGGER.warn("Error closing AdminClient: {}", e.getMessage());
      }
    }
  }

  private Map<String, TopicDescription> describeTopics(Collection<String> topicNames) {
    LOGGER.debug("Describing topics: {}", topicNames);

    try {
      DescribeTopicsResult result = adminClient.describeTopics(topicNames);
      return result.allTopicNames().get();
    } catch (Exception e) {
      if (e.getCause() instanceof UnknownTopicOrPartitionException) {
        LOGGER.debug("Some topics don't exist, checking individually");
        return describeTopicsIndividually(topicNames);
      }

      LOGGER.error("Failed to describe topics: {}", e.getMessage());
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      return null;
    }
  }

  private Map<String, TopicDescription> describeTopicsIndividually(Collection<String> topicNames) {
    Map<String, TopicDescription> descriptions = new HashMap<>();

    for (String topicName : topicNames) {
      try {
        DescribeTopicsResult result =
            adminClient.describeTopics(Collections.singleton(topicName));
        Map<String, TopicDescription> singleTopicDesc = result.allTopicNames().get();
        descriptions.putAll(singleTopicDesc);
      } catch (Exception e) {
        if (e.getCause() instanceof UnknownTopicOrPartitionException) {
          LOGGER.warn("Topic {} does not exist, skipping from validation", topicName);
        } else if (e instanceof InterruptedException) {
          Thread.currentThread().interrupt();
          LOGGER.error("Interrupted while describing topic: {}", topicName);
          return descriptions;
        } else {
          LOGGER.warn("Failed to describe topic {}: {}", topicName, e.getMessage());
        }
      }
    }
    return descriptions;
  }

  @VisibleForTesting
  void validateTaskToTopicPartitions() {
    LOGGER.debug("Validating task to topic partitions configuration...");

    // Get topics from config
    List<String> topics = getTopicsFromConfig();

    // Get tasks.max from config
    int maxTasks = 1;
    String maxTasksStr = config.get("tasks.max");
    if (maxTasksStr != null) {
      try {
        maxTasks = Integer.parseInt(maxTasksStr);
      } catch (NumberFormatException e) {
        LOGGER.warn("Invalid tasks.max value: {}, using default 1", maxTasksStr);
      }
    }

    // Get partition counts
    Map<String, TopicDescription> descriptions = describeTopics(topics);
    if (descriptions == null) {
      LOGGER.error("Could not describe topics, skipping validating TaskToTopicPartitions.");
      return;
    }

    if (descriptions.isEmpty()) {
      LOGGER.warn("No valid topics found for validation. Topics requested: {}", topics);
      return;
    }

    int totalPartitions = 0;
    for (TopicDescription desc : descriptions.values()) {
      totalPartitions += desc.partitions().size();
    }

    // Calculate partitions per task, assumes even partition distribution across tasks
    int partitionsPerTask = (totalPartitions + maxTasks - 1) / maxTasks; // Ceiling division
    LOGGER.info(
        "Total partitions: {}, Max Tasks: {}, Partitions per task: {}, Max allowed partitions per"
            + " task: {}",
        totalPartitions,
        maxTasks,
        partitionsPerTask,
        this.maxTopicPartitionsPerTask);

    if (partitionsPerTask > this.maxTopicPartitionsPerTask) {
      // Calculate minimum required tasks
      int requiredTasks =
          (totalPartitions + this.maxTopicPartitionsPerTask - 1) / this.maxTopicPartitionsPerTask;
      String errorMessage;
      if (this.enableDynamicFlush) {
        // Dynamic flush already enabled, just suggest increasing tasks
        errorMessage =
            String.format(
                "Partitions per task (%d) exceeds maximum allowed partitions (%d). Please increase"
                    + " the tasks.max to at least %d to ensure each task handles at most %d"
                    + " partitions.",
                partitionsPerTask,
                this.maxTopicPartitionsPerTask,
                requiredTasks,
                this.maxTopicPartitionsPerTask);
      } else {
        // Dynamic flush not enabled, suggest both options
        int maxTopicPartitionsWithDynamicFlush =
            this.maxTopicPartitionsPerTask * RELAXED_MULTIPLIER;
        int requiredTasksWithDynamicFlush =
            (totalPartitions + maxTopicPartitionsWithDynamicFlush - 1)
                / maxTopicPartitionsWithDynamicFlush;
        errorMessage =
            String.format(
                "Partitions per task (%d) exceeds maximum allowed partitions (%d). Please increase"
                    + " the tasks.max to at least %d, or enable %s which"
                    + " would allow %d partitions per task and ensure the tasks.max is at least"
                    + " %d.",
                partitionsPerTask,
                this.maxTopicPartitionsPerTask,
                requiredTasks,
                ENABLE_DYNAMIC_FLUSH,
                maxTopicPartitionsWithDynamicFlush,
                requiredTasksWithDynamicFlush);
      }
      if (this.failureAction == TaskToTopicPartitionValidatorFailureAction.FAIL) {
        LOGGER.error(errorMessage);
        // This will be caught by the run() loop and call fail()
        throw new ConnectException(errorMessage);
      } else {
        LOGGER.warn(errorMessage);
      }
    }
  }

  private List<String> getTopicsFromConfig() {
    String topicsStr = config.get(SnowflakeSinkConnectorConfig.TOPICS);
    // Case 1: Explicit topics are configured
    if (topicsStr != null && !topicsStr.trim().isEmpty()) {
      return Arrays.stream(topicsStr.split(","))
          .map(String::trim)
          .filter(s -> !s.isEmpty())
          .collect(Collectors.toList());
    }

    // Case 2: Fall back to regex-based topic discovery
    LOGGER.debug("No topics configured, trying with {}", SnowflakeSinkConnectorConfig.TOPICS_REGEX);
    String topicsRegex = config.get(SnowflakeSinkConnectorConfig.TOPICS_REGEX);
    if (topicsRegex == null || topicsRegex.trim().isEmpty()) {
      LOGGER.warn("Neither TOPICS nor TOPICS_REGEX is configured");
      return Collections.emptyList();
    }

    try {
      Set<String> topics = adminClient.listTopics().names().get();
      Pattern pattern = Pattern.compile(topicsRegex);

      List<String> matchingTopics = new ArrayList<>();
      for (String topic : topics) {
        if (pattern.matcher(topic).matches()) {
          matchingTopics.add(topic);
        }
      }
      return matchingTopics;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      LOGGER.error("Interrupted while listing topics for regex matching", e);
    } catch (ExecutionException e) {
      LOGGER.error("Error listing topics for regex matching", e);
    }
    return Collections.emptyList();
  }

  /**
   * Fail the connector with an unrecoverable error and stop the validator thread if the failure
   * action is set to FAIL. Otherwise, just log the error.
   *
   * @param t the cause of the failure
   * @param message additional message to log with the error
   */
  private void fail(Throwable t, String message) {
    if (this.failureAction == TaskToTopicPartitionValidatorFailureAction.FAIL) {
      shutdownLatch.countDown();
      LOGGER.error(message, t);
      RuntimeException exception = new ConnectException(message, t);
      failure.set(exception);
      throw exception;
    } else {
      LOGGER.warn(message, t);
    }
  }
}
