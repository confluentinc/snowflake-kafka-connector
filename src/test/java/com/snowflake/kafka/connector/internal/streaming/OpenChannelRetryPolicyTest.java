package com.snowflake.kafka.connector.internal.streaming;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.failsafe.function.CheckedSupplier;
import java.util.concurrent.atomic.AtomicInteger;
import net.snowflake.ingest.streaming.SnowflakeStreamingIngestChannel;
import net.snowflake.ingest.utils.ErrorCode;
import net.snowflake.ingest.utils.SFException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

public class OpenChannelRetryPolicyTest {

  private static final String EXCEPTION_429_MSG =
      "Open channel request failed: HTTP Status: 429 ErrorBody: {\n"
          + "\"status_code\" : 87,\n"
          + "\"message\" : \"Cannot open channel at this time due to a high number of pending"
          + " open channel requests on the table.\"\n"
          + "}.";

  @Mock private SnowflakeStreamingIngestChannel mockChannel;

  private final String channelName = "test_channel";

  @BeforeEach
  void setUp() {
    MockitoAnnotations.initMocks(this);
  }

  @Test
  void shouldReturnChannelOnFirstAttemptSuccess() {
    // Given
    CheckedSupplier<SnowflakeStreamingIngestChannel> supplier = () -> mockChannel;

    // When
    SnowflakeStreamingIngestChannel result =
        OpenChannelRetryPolicy.executeWithRetry(supplier, channelName);

    // Then
    assertSame(mockChannel, result);
  }

  @Test
  void shouldNotRetryOnNonSFException() {
    // Given
    IllegalArgumentException nonRetryableException = new IllegalArgumentException("Non-retryable");
    CheckedSupplier<SnowflakeStreamingIngestChannel> supplier =
        () -> {
          throw nonRetryableException;
        };

    // When/Then
    IllegalArgumentException thrownException =
        assertThrows(
            IllegalArgumentException.class,
            () -> OpenChannelRetryPolicy.executeWithRetry(supplier, channelName));

    assertSame(nonRetryableException, thrownException);
  }

  @Test
  void shouldNotRetryOnSFExceptionWithout429() {
    // Given
    SFException nonRetryableException =
        new SFException(ErrorCode.OPEN_CHANNEL_FAILURE, "Some other error");
    AtomicInteger attemptCount = new AtomicInteger(0);
    CheckedSupplier<SnowflakeStreamingIngestChannel> supplier =
        () -> {
          attemptCount.incrementAndGet();
          throw nonRetryableException;
        };

    // When/Then
    SFException thrownException =
        assertThrows(
            SFException.class,
            () -> OpenChannelRetryPolicy.executeWithRetry(supplier, channelName));

    assertSame(nonRetryableException, thrownException);
    assertEquals(1, attemptCount.get()); // Should only attempt once
  }

  @Test
  void shouldRetryMultipleTimesOn429Exception() {
    // Given
    SFException exception429 = new SFException(ErrorCode.INTERNAL_ERROR, EXCEPTION_429_MSG);
    AtomicInteger attemptCount = new AtomicInteger(0);

    CheckedSupplier<SnowflakeStreamingIngestChannel> supplier =
        () -> {
          int attempt = attemptCount.incrementAndGet();
          if (attempt <= 2) {
            throw exception429; // Fail first 2 attempts with 429
          }
          return mockChannel; // Succeed on 3rd attempt
        };

    // When
    SnowflakeStreamingIngestChannel result =
        OpenChannelRetryPolicy.executeWithRetry(supplier, channelName);

    // Then
    assertSame(mockChannel, result);
    assertEquals(3, attemptCount.get()); // Verify it retried 2 times before succeeding
  }

  @Test
  void shouldThrowSFExceptionAfterAllRetriesExhaustedWithNoMoreAttempts() {
    // Given - MAX_ATTEMPTS is 10 in OpenChannelRetryPolicy
    SFException exception429 = new SFException(ErrorCode.INTERNAL_ERROR, EXCEPTION_429_MSG);
    AtomicInteger attemptCount = new AtomicInteger(0);

    CheckedSupplier<SnowflakeStreamingIngestChannel> supplier =
        () -> {
          int currentAttempt = attemptCount.incrementAndGet();
          // If we ever reach 11, fail the test - there should be no 11th attempt
          if (currentAttempt > 10) {
            throw new AssertionError(
                "Should not attempt more than 10 times, but got attempt #" + currentAttempt);
          }
          throw exception429; // Always fail with 429
        };

    // When/Then - should throw SFException after all retries exhausted
    SFException thrownException =
        assertThrows(
            SFException.class,
            () -> OpenChannelRetryPolicy.executeWithRetry(supplier, channelName));

    // Verify the original SFException is thrown with 429 error
    assertTrue(thrownException.getMessage().contains("HTTP Status: 429"));
    // Verify exactly 10 attempts - no more (no 11th attempt), no less
    assertEquals(10, attemptCount.get(), "Expected exactly 10 attempts");
  }
}
