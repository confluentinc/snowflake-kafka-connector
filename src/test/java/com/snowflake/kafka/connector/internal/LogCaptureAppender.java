/*
 * Copyright (c) 2024 Snowflake Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.snowflake.kafka.connector.internal;

import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Test-only log4j appender that captures the rendered messages emitted by a given logger. The
 * connector logs through SLF4J bound to log4j 1.x in tests (see
 * src/test/resources/log4j.properties), so attaching here captures exactly what would be written to
 * a file/OpenSearch appender in production.
 */
public class LogCaptureAppender extends AppenderSkeleton {

  private final List<String> messages = new ArrayList<>();
  private final String loggerName;
  private final Level previousLevel;
  private final Logger logger;

  private LogCaptureAppender(String loggerName) {
    this.loggerName = loggerName;
    this.logger = Logger.getLogger(loggerName);
    this.previousLevel = logger.getLevel();
  }

  /** Attach a fresh capturing appender to the given logger and ensure ERROR is not filtered out. */
  public static LogCaptureAppender attachTo(String loggerName) {
    LogCaptureAppender appender = new LogCaptureAppender(loggerName);
    appender.logger.addAppender(appender);
    appender.logger.setLevel(Level.ALL);
    return appender;
  }

  /** Detach and restore the logger's previous level. */
  public void detach() {
    logger.removeAppender(this);
    logger.setLevel(previousLevel);
  }

  @Override
  protected void append(LoggingEvent event) {
    messages.add(String.valueOf(event.getRenderedMessage()));
  }

  public List<String> messages() {
    return messages;
  }

  /** True if any captured message contains the given substring. */
  public boolean anyMessageContains(String needle) {
    for (String m : messages) {
      if (m != null && m.contains(needle)) {
        return true;
      }
    }
    return false;
  }

  @Override
  public void close() {}

  @Override
  public boolean requiresLayout() {
    return false;
  }
}
