package com.snowflake.kafka.connector.internal.streaming;

import com.snowflake.kafka.connector.Utils;
import java.util.HashMap;
import java.util.Map;
import net.snowflake.ingest.utils.Constants;

/* Utility class/Helper methods for streaming related ingestion. */
public class StreamingUtils {
  /* Maps streaming client's property keys to what we got from snowflake KC config file. */
  public static Map<String, String> convertConfigForStreamingClient(
      Map<String, String> connectorConfig) {
    Map<String, String> streamingPropertiesMap = new HashMap<>();
    connectorConfig.computeIfPresent(
        Utils.SF_URL,
        (key, value) -> {
          streamingPropertiesMap.put(Constants.ACCOUNT_URL, value);
          return value;
        });

    connectorConfig.computeIfPresent(
        Utils.SF_ROLE,
        (key, value) -> {
          streamingPropertiesMap.put(Constants.ROLE, value);
          return value;
        });

    connectorConfig.computeIfPresent(
        Utils.SF_USER,
        (key, value) -> {
          streamingPropertiesMap.put(Constants.USER, value);
          return value;
        });

    connectorConfig.computeIfPresent(
        Utils.SF_PRIVATE_KEY,
        (key, value) -> {
          streamingPropertiesMap.put(Constants.PRIVATE_KEY, value);
          return value;
        });

    connectorConfig.computeIfPresent(
        Utils.PRIVATE_KEY_PASSPHRASE,
        (key, value) -> {
          if (!value.isEmpty()) {
            streamingPropertiesMap.put(Constants.PRIVATE_KEY_PASSPHRASE, value);
          }
          return value;
        });
    return streamingPropertiesMap;
  }
}
