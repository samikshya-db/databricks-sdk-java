// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.

package com.databricks.sdk.service.database;

import com.databricks.sdk.support.Generated;
import com.databricks.sdk.support.ToStringer;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** Status of a synced table. */
@Generated
public class SyncedTableStatus {
  /**
   * Detailed status of a synced table. Shown if the synced table is in the SYNCED_CONTINUOUS_UPDATE
   * or the SYNCED_UPDATING_PIPELINE_RESOURCES state.
   */
  @JsonProperty("continuous_update_status")
  private SyncedTableContinuousUpdateStatus continuousUpdateStatus;

  /** The state of the synced table. */
  @JsonProperty("detailed_state")
  private SyncedTableState detailedState;

  /**
   * Detailed status of a synced table. Shown if the synced table is in the OFFLINE_FAILED or the
   * SYNCED_PIPELINE_FAILED state.
   */
  @JsonProperty("failed_status")
  private SyncedTableFailedStatus failedStatus;

  /** A text description of the current state of the synced table. */
  @JsonProperty("message")
  private String message;

  /**
   * Detailed status of a synced table. Shown if the synced table is in the
   * PROVISIONING_PIPELINE_RESOURCES or the PROVISIONING_INITIAL_SNAPSHOT state.
   */
  @JsonProperty("provisioning_status")
  private SyncedTableProvisioningStatus provisioningStatus;

  /**
   * Detailed status of a synced table. Shown if the synced table is in the SYNCED_TRIGGERED_UPDATE
   * or the SYNCED_NO_PENDING_UPDATE state.
   */
  @JsonProperty("triggered_update_status")
  private SyncedTableTriggeredUpdateStatus triggeredUpdateStatus;

  public SyncedTableStatus setContinuousUpdateStatus(
      SyncedTableContinuousUpdateStatus continuousUpdateStatus) {
    this.continuousUpdateStatus = continuousUpdateStatus;
    return this;
  }

  public SyncedTableContinuousUpdateStatus getContinuousUpdateStatus() {
    return continuousUpdateStatus;
  }

  public SyncedTableStatus setDetailedState(SyncedTableState detailedState) {
    this.detailedState = detailedState;
    return this;
  }

  public SyncedTableState getDetailedState() {
    return detailedState;
  }

  public SyncedTableStatus setFailedStatus(SyncedTableFailedStatus failedStatus) {
    this.failedStatus = failedStatus;
    return this;
  }

  public SyncedTableFailedStatus getFailedStatus() {
    return failedStatus;
  }

  public SyncedTableStatus setMessage(String message) {
    this.message = message;
    return this;
  }

  public String getMessage() {
    return message;
  }

  public SyncedTableStatus setProvisioningStatus(SyncedTableProvisioningStatus provisioningStatus) {
    this.provisioningStatus = provisioningStatus;
    return this;
  }

  public SyncedTableProvisioningStatus getProvisioningStatus() {
    return provisioningStatus;
  }

  public SyncedTableStatus setTriggeredUpdateStatus(
      SyncedTableTriggeredUpdateStatus triggeredUpdateStatus) {
    this.triggeredUpdateStatus = triggeredUpdateStatus;
    return this;
  }

  public SyncedTableTriggeredUpdateStatus getTriggeredUpdateStatus() {
    return triggeredUpdateStatus;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    SyncedTableStatus that = (SyncedTableStatus) o;
    return Objects.equals(continuousUpdateStatus, that.continuousUpdateStatus)
        && Objects.equals(detailedState, that.detailedState)
        && Objects.equals(failedStatus, that.failedStatus)
        && Objects.equals(message, that.message)
        && Objects.equals(provisioningStatus, that.provisioningStatus)
        && Objects.equals(triggeredUpdateStatus, that.triggeredUpdateStatus);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        continuousUpdateStatus,
        detailedState,
        failedStatus,
        message,
        provisioningStatus,
        triggeredUpdateStatus);
  }

  @Override
  public String toString() {
    return new ToStringer(SyncedTableStatus.class)
        .add("continuousUpdateStatus", continuousUpdateStatus)
        .add("detailedState", detailedState)
        .add("failedStatus", failedStatus)
        .add("message", message)
        .add("provisioningStatus", provisioningStatus)
        .add("triggeredUpdateStatus", triggeredUpdateStatus)
        .toString();
  }
}
