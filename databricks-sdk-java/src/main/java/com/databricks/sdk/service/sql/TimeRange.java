// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.

package com.databricks.sdk.service.sql;

import com.databricks.sdk.support.Generated;
import com.databricks.sdk.support.QueryParam;
import com.databricks.sdk.support.ToStringer;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

@Generated
public class TimeRange {
  /** The end time in milliseconds. */
  @JsonProperty("end_time_ms")
  @QueryParam("end_time_ms")
  private Long endTimeMs;

  /** The start time in milliseconds. */
  @JsonProperty("start_time_ms")
  @QueryParam("start_time_ms")
  private Long startTimeMs;

  public TimeRange setEndTimeMs(Long endTimeMs) {
    this.endTimeMs = endTimeMs;
    return this;
  }

  public Long getEndTimeMs() {
    return endTimeMs;
  }

  public TimeRange setStartTimeMs(Long startTimeMs) {
    this.startTimeMs = startTimeMs;
    return this;
  }

  public Long getStartTimeMs() {
    return startTimeMs;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    TimeRange that = (TimeRange) o;
    return Objects.equals(endTimeMs, that.endTimeMs)
        && Objects.equals(startTimeMs, that.startTimeMs);
  }

  @Override
  public int hashCode() {
    return Objects.hash(endTimeMs, startTimeMs);
  }

  @Override
  public String toString() {
    return new ToStringer(TimeRange.class)
        .add("endTimeMs", endTimeMs)
        .add("startTimeMs", startTimeMs)
        .toString();
  }
}
