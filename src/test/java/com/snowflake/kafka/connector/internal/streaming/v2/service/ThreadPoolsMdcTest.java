package com.snowflake.kafka.connector.internal.streaming.v2.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.snowflake.kafka.connector.config.SinkTaskConfig;
import com.snowflake.kafka.connector.config.SinkTaskConfigTestBuilder;
import com.snowflake.kafka.connector.internal.KCLogger;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

/**
 * Kafka Connect sets the {@code connector.context} MDC entry only on the task thread. Work handed
 * to the connector's pools must carry the submitting task's entry, or its log lines lose the
 * connector and task id, or show another task's.
 *
 * <p>Each test starts the pool threads before setting the MDC. A new thread can copy the MDC of
 * the thread that created it (reload4j, which the tests use, does this, and so does log4j2 with
 * {@code log4j2.isThreadContextMapInheritable=true}), so a fresh thread can hide the bug. A reused
 * thread shows the real behaviour.
 */
class ThreadPoolsMdcTest {

  private String connectorName;

  @BeforeEach
  void setUp() throws Exception {
    MDC.clear();
    connectorName = "mdc_test_" + UUID.randomUUID();
    SinkTaskConfig config =
        SinkTaskConfigTestBuilder.builder()
            .connectorName(connectorName)
            .taskId("0")
            .openChannelIoThreads(1)
            .build();
    ThreadPools.registerTask(connectorName, config);
    startPoolThread(ThreadPools.getIoExecutor(connectorName));
    startPoolThread(ThreadPools.getOpenChannelIoExecutor(connectorName));
  }

  @AfterEach
  void tearDown() {
    ThreadPools.closeForTask(connectorName);
    MDC.clear();
  }

  @Test
  void ioExecutorRunsWithTheSubmittersMdc() throws Exception {
    MDC.put(KCLogger.MDC_CONN_CTX_KEY, "[lcc-abc123|task-0] ");
    assertThat(contextSeenBy(ThreadPools.getIoExecutor(connectorName)))
        .isEqualTo("[lcc-abc123|task-0] ");
  }

  @Test
  void openChannelExecutorRunsWithTheSubmittersMdc() throws Exception {
    MDC.put(KCLogger.MDC_CONN_CTX_KEY, "[lcc-abc123|task-0] ");
    assertThat(contextSeenBy(ThreadPools.getOpenChannelIoExecutor(connectorName)))
        .isEqualTo("[lcc-abc123|task-0] ");
  }

  @Test
  void reusedPoolThreadTakesEachSubmittersMdcAndKeepsNoneAfterwards() throws Exception {
    ExecutorService executor = ThreadPools.getOpenChannelIoExecutor(connectorName);

    MDC.put(KCLogger.MDC_CONN_CTX_KEY, "[lcc-a|task-0] ");
    assertThat(contextSeenBy(executor)).isEqualTo("[lcc-a|task-0] ");

    MDC.put(KCLogger.MDC_CONN_CTX_KEY, "[lcc-a|task-1] ");
    assertThat(contextSeenBy(executor)).isEqualTo("[lcc-a|task-1] ");

    MDC.clear();
    assertThat(contextSeenBy(executor)).isNull();
  }

  /** Creates the pool's thread with no MDC and lets it go idle so the next task reuses it. */
  private static void startPoolThread(ExecutorService executor) throws Exception {
    CompletableFuture.runAsync(() -> {}, executor).get();
    Thread.sleep(100);
  }

  private static String contextSeenBy(ExecutorService executor) throws Exception {
    return CompletableFuture.supplyAsync(() -> MDC.get(KCLogger.MDC_CONN_CTX_KEY), executor).get();
  }
}
