package com.snowflake.kafka.connector.internal;

import com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import com.snowflake.kafka.connector.Utils;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.DescribeTopicsResult;
import org.apache.kafka.clients.admin.TopicDescription;
import org.apache.kafka.common.KafkaException;
import org.apache.kafka.connect.errors.ConnectException;

import static com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.TASK_TO_TOPIC_PARTITIONS_MEMORY_LIMIT_IN_BYTES;
import static com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig.TASK_TO_TOPIC_PARTITIONS_VALIDATION_INTERVAL_MS;

/**
 * Thread that periodically validates that the total memory usage (partitions * buffer size) does
 * not exceed a safety threshold.
 *
 * <p>This class handles its own Kafka AdminClient lifecycle for checking partition counts.
 */
public class TaskToTopicPartitionValidator extends Thread {
  private static final KCLogger LOGGER =
      new KCLogger(TaskToTopicPartitionValidator.class.getName());
  private static final long DEFAULT_MEMORY_LIMIT_BYTES = 500 * 1024 * 1024; // 500MB
  private static final long DEFAULT_VALIDATION_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

  private final Map<String, String> config;
  private final AtomicReference<Throwable> failure;
  private final CountDownLatch shutdownLatch;
  private final long validationIntervalMs;
  private final long memoryLimitBytes;
  private AdminClient adminClient;

  public TaskToTopicPartitionValidator(Map<String, String> config, AtomicReference<Throwable> failure, String taskConfigId) {
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
    this.validationIntervalMs = Long.parseLong(
        config.getOrDefault(
            TASK_TO_TOPIC_PARTITIONS_VALIDATION_INTERVAL_MS,
            String.valueOf(DEFAULT_VALIDATION_INTERVAL_MS)
        )
    );
    this.memoryLimitBytes = Long.parseLong(
        config.getOrDefault(
            TASK_TO_TOPIC_PARTITIONS_MEMORY_LIMIT_IN_BYTES,
            String.valueOf(DEFAULT_MEMORY_LIMIT_BYTES)
        )
    );
    this.shutdownLatch = new CountDownLatch(1);
    this.setName(config.get(Utils.NAME) + "-" + taskConfigId + "-task-to-topic-partitions-validator");
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
        throw fail(e);
      }
    }

    while (shutdownLatch.getCount() > 0) {
      try {
        validateTaskToTopicPartitions();
      } catch (ConnectException e) {
        throw fail(e);
      }

      try {
        LOGGER.debug("Waiting {} ms to check for buffer size validation.", validationIntervalMs);
        boolean shuttingDown = shutdownLatch.await(validationIntervalMs, TimeUnit.MILLISECONDS);
        if (shuttingDown) {
          return;
        }
      } catch (InterruptedException e) {
        LOGGER.error("Unexpected InterruptedException, ignoring: ", e);
      }
    }
  }

  public void shutdown() {
    LOGGER.info("Shutting down TaskToTopicPartitionValidator thread.");
    shutdownLatch.countDown();
    closeAdminClient();
  }

  /**
   * Run initial validation synchronously before starting the thread.
   * This method should be called before start() to fail fast if validation fails.
   *
   * @throws ConnectException if validation fails
   */
  public void runInitialValidation() {
    LOGGER.info("Running initial TaskToTopicPartition validation...");
    if (this.adminClient == null) {
      initializeAdminClient();
    }
    // Run validation - will throw ConnectException if it fails
    validateTaskToTopicPartitions();
    LOGGER.info("Initial TaskToTopicPartition validation passed.");
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
      LOGGER.error("Failed to describe topics: {}", e.getMessage());
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      return null;
    }
  }

  // Visible for testing
  void validateTaskToTopicPartitions() {
    LOGGER.debug("Validating buffer size configuration...");

    // Get topics from config
    String topicsStr = config.get(SnowflakeSinkConnectorConfig.TOPICS);
    if (topicsStr == null || topicsStr.isEmpty()) {
      LOGGER.debug("No topics configured, skipping validation");
      return;
    }
    List<String> topics = Arrays.asList(topicsStr.split(","));

    // Get buffer size from config
    long bufferSizeBytes = SnowflakeSinkConnectorConfig.BUFFER_SIZE_BYTES_DEFAULT;
    String bufferSizeStr = config.get(SnowflakeSinkConnectorConfig.BUFFER_SIZE_BYTES);
    if (bufferSizeStr != null) {
      try {
        bufferSizeBytes = Long.parseLong(bufferSizeStr);
      } catch (NumberFormatException e) {
        LOGGER.warn("Invalid buffer.size.bytes value: {}, using default", bufferSizeStr);
      }
    }

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
      LOGGER.warn("Could not describe topics, skipping validating TaskToTopicPartitions.");
      return;
    }

    int totalPartitions = 0;
    for (TopicDescription desc : descriptions.values()) {
      totalPartitions += desc.partitions().size();
    }

    // Calculate total memory usage
    long totalMemoryUsage = (totalPartitions * bufferSizeBytes) / maxTasks;
    LOGGER.info(
        "Total partitions: {}, Buffer size: {}, Max Tasks: {}, Total potential memory usage per task: {} bytes",
        totalPartitions,
        bufferSizeBytes,
        maxTasks,
        totalMemoryUsage);

    if (totalMemoryUsage > this.memoryLimitBytes) {
      long requiredTasks =
          (totalPartitions * bufferSizeBytes + this.memoryLimitBytes - 1) / this.memoryLimitBytes;
      String errorMessage =
          String.format(
              "Total memory usage per task (%d bytes) exceeds limit (%d bytes). "
                  + "Please increase tasks.max to at least %d or decrease buffer.size.bytes",
              totalMemoryUsage, this.memoryLimitBytes, requiredTasks);

      // This will be caught by the run() loop and call fail()
      throw new ConnectException(errorMessage);
    }
  }

  /**
   * Fail the connector with an unrecoverable error and stop the validator thread
   *
   * @param t the cause of the failure
   * @return a {@link RuntimeException} that can be thrown from the calling method
   */
  private RuntimeException fail(Throwable t) {
    String message = "Encountered an unrecoverable error during task to topic partition validation";
    LOGGER.error(message, t);
    RuntimeException exception = new ConnectException(message, t);
    failure.set(t);
    // Preemptively shut down the monitoring thread
    shutdownLatch.countDown();
    return exception;
  }
}
