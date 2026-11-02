package com.snowflake.kafka.connector.internal;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

class MdcPropagationTest {

  @AfterEach
  void tearDown() {
    MDC.clear();
  }

  @Test
  void wrappedTaskSeesTheCallersMdcOnAnotherThread() throws Exception {
    ExecutorService executor = Executors.newSingleThreadExecutor();
    try {
      // Start the thread with no MDC, so a backend that copies the MDC into new threads cannot
      // hide a missing propagation.
      executor.submit(() -> {}).get();

      MDC.put(KCLogger.MDC_CONN_CTX_KEY, "[lcc-abc123|task-0] ");
      AtomicReference<String> seen = new AtomicReference<>();
      executor
          .submit(MdcPropagation.wrap(() -> seen.set(MDC.get(KCLogger.MDC_CONN_CTX_KEY))))
          .get();

      assertThat(seen.get()).isEqualTo("[lcc-abc123|task-0] ");
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  void wrappedTaskPutsTheRunningThreadsOwnMdcBack() {
    MDC.put(KCLogger.MDC_CONN_CTX_KEY, "[lcc-abc123|task-0] ");
    AtomicReference<String> seen = new AtomicReference<>();
    Runnable task = MdcPropagation.wrap(() -> seen.set(MDC.get(KCLogger.MDC_CONN_CTX_KEY)));

    MDC.put(KCLogger.MDC_CONN_CTX_KEY, "[lcc-other|task-3] ");
    task.run();

    assertThat(seen.get()).isEqualTo("[lcc-abc123|task-0] ");
    assertThat(MDC.get(KCLogger.MDC_CONN_CTX_KEY)).isEqualTo("[lcc-other|task-3] ");
  }

  @Test
  void wrappedTaskCreatedWithoutMdcRunsWithoutMdc() {
    Runnable task =
        MdcPropagation.wrap(() -> assertThat(MDC.get(KCLogger.MDC_CONN_CTX_KEY)).isNull());

    MDC.put(KCLogger.MDC_CONN_CTX_KEY, "[lcc-other|task-3] ");
    task.run();

    assertThat(MDC.get(KCLogger.MDC_CONN_CTX_KEY)).isEqualTo("[lcc-other|task-3] ");
  }
}
