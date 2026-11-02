package com.snowflake.kafka.connector.internal;

import java.util.List;
import java.util.Map;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import org.slf4j.MDC;

/**
 * Carries the caller's MDC into work that runs on another thread.
 *
 * <p>Kafka Connect sets the {@code connector.context} MDC entry ({@link KCLogger#MDC_CONN_CTX_KEY})
 * only on the task thread. Confluent Cloud shows a connector's log lines to the customer only when
 * they carry that entry, so work that the task hands to a thread pool must take it along.
 */
public final class MdcPropagation {

  private MdcPropagation() {}

  /**
   * Returns a runnable that runs {@code task} with the MDC of the thread calling this method, and
   * puts the running thread's own MDC back afterwards.
   */
  public static Runnable wrap(final Runnable task) {
    final Map<String, String> callerContext = MDC.getCopyOfContextMap();
    return () -> {
      final Map<String, String> previousContext = MDC.getCopyOfContextMap();
      setContext(callerContext);
      try {
        task.run();
      } finally {
        setContext(previousContext);
      }
    };
  }

  /**
   * Returns an executor service that runs every submitted task with the MDC of the thread that
   * submitted it. Shutting down the returned service shuts down {@code delegate}.
   */
  public static ExecutorService propagating(final ExecutorService delegate) {
    return new MdcPropagatingExecutorService(delegate);
  }

  private static void setContext(final Map<String, String> context) {
    if (context == null) {
      MDC.clear();
    } else {
      MDC.setContextMap(context);
    }
  }

  private static final class MdcPropagatingExecutorService extends AbstractExecutorService {
    private final ExecutorService delegate;

    MdcPropagatingExecutorService(final ExecutorService delegate) {
      this.delegate = delegate;
    }

    @Override
    public void execute(final Runnable command) {
      delegate.execute(wrap(command));
    }

    @Override
    public void shutdown() {
      delegate.shutdown();
    }

    @Override
    public List<Runnable> shutdownNow() {
      return delegate.shutdownNow();
    }

    @Override
    public boolean isShutdown() {
      return delegate.isShutdown();
    }

    @Override
    public boolean isTerminated() {
      return delegate.isTerminated();
    }

    @Override
    public boolean awaitTermination(final long timeout, final TimeUnit unit)
        throws InterruptedException {
      return delegate.awaitTermination(timeout, unit);
    }
  }
}
