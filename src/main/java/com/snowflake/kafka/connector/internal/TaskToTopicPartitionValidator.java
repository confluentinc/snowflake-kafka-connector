package com.snowflake.kafka.connector.internal;

import com.snowflake.kafka.connector.SnowflakeSinkConnectorConfig;

import java.net.ConnectException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.*;

import net.snowflake.client.jdbc.internal.google.common.util.concurrent.ThreadFactoryBuilder;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.DescribeTopicsResult;
import org.apache.kafka.clients.admin.TopicDescription;
import org.apache.kafka.common.KafkaException;

/**
 * Periodically validates that the total memory usage (partitions * buffer size) does not exceed a
 * safety threshold.
 *
 * <p>This class handles its own Kafka AdminClient lifecycle for checking partition counts.
 */
public class TaskToTopicPartitionValidator {
  private static final KCLogger LOGGER =
      new KCLogger(TaskToTopicPartitionValidator.class.getName());
  private static final long MEMORY_LIMIT_BYTES = 500 * 1024 * 1024; // 500MB
  private static final long VALIDATION_INTERVAL_MINUTES = 5; // Run every 5 minutes

  private final ScheduledExecutorService scheduler;
  private final Map<String, String> config;
  private AdminClient adminClient;

  public TaskToTopicPartitionValidator(Map<String, String> config) {
    this(config, null);
  }

  public TaskToTopicPartitionValidator(Map<String, String> config, AdminClient adminClient) {
    this.config = config;
    this.scheduler = Executors.newSingleThreadScheduledExecutor(
        new ThreadFactoryBuilder().setNameFormat("task-to-topic-partitions-validator").build()
    );
    this.adminClient = adminClient;
  }

  public void start() {
    LOGGER.info("Starting TaskToTopicPartitionValidator scheduler");
    // Initialize AdminClient if not provided
    if (this.adminClient == null) {
      initializeAdminClient();
    }

    scheduler.scheduleAtFixedRate(
        this::validateTaskToTopicPartitions, 0, VALIDATION_INTERVAL_MINUTES, TimeUnit.MINUTES);
  }

  public void stop() {
    LOGGER.info("Stopping TaskToTopicPartitionValidator scheduler");
    scheduler.shutdown();
    try {
      if (!scheduler.awaitTermination(10, TimeUnit.SECONDS)) {
        scheduler.shutdownNow();
      }
    } catch (InterruptedException e) {
      scheduler.shutdownNow();
      Thread.currentThread().interrupt();
    }
    closeAdminClient();
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
    } catch (InterruptedException | ExecutionException e) {
      LOGGER.error("Failed to describe topics: {}", e.getMessage());
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      // We don't throw here to avoid killing the scheduler thread entirely,
      // just return null or empty so we can retry next time
      return null;
    }
  }

  // Visible for testing
  void validateTaskToTopicPartitions() {
    try {
      LOGGER.info("Validating buffer size configuration...");

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
      // remove this condition ( not needed probably )
      if (maxTasks < 1) {
        maxTasks = 1;
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
          "Total partitions: {}, Buffer size: {}, Max Tasks: {}, Total memory usage: {} bytes",
          totalPartitions,
          bufferSizeBytes,
          maxTasks,
          totalMemoryUsage);

      if (totalMemoryUsage > MEMORY_LIMIT_BYTES) {
        long requiredTasks = (totalPartitions * bufferSizeBytes + MEMORY_LIMIT_BYTES - 1) / MEMORY_LIMIT_BYTES;
        String errorMessage =
            String.format(
                "Total memory usage per task (%d bytes) exceeds limit (%d bytes). "
                    + "Please increase tasks.max to at least %d or decrease buffer.size.bytes",
                totalMemoryUsage, MEMORY_LIMIT_BYTES, requiredTasks);

        LOGGER.error(errorMessage);
        throw new RuntimeException(errorMessage);
      }

    } catch (RuntimeException ce) {
      // MUST rethrow so the connector actually stops
      throw ce;
    } catch (Exception e) {
      LOGGER.error("Error during buffer size validation: {}", e.getMessage());
    }
  }
}
