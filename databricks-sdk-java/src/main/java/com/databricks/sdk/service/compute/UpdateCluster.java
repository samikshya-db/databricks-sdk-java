// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.

package com.databricks.sdk.service.compute;

import com.databricks.sdk.support.Generated;
import com.databricks.sdk.support.ToStringer;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

@Generated
public class UpdateCluster {
  /** The cluster to be updated. */
  @JsonProperty("cluster")
  private UpdateClusterResource cluster;

  /** ID of the cluster. */
  @JsonProperty("cluster_id")
  private String clusterId;

  /**
   * Used to specify which cluster attributes and size fields to update. See
   * https://google.aip.dev/161 for more details.
   *
   * <p>The field mask must be a single string, with multiple fields separated by commas (no
   * spaces). The field path is relative to the resource object, using a dot (`.`) to navigate
   * sub-fields (e.g., `author.given_name`). Specification of elements in sequence or map fields is
   * not allowed, as only the entire collection field can be specified. Field names must exactly
   * match the resource field names.
   *
   * <p>A field mask of `*` indicates full replacement. It’s recommended to always explicitly list
   * the fields being updated and avoid using `*` wildcards, as it can lead to unintended results if
   * the API changes in the future.
   */
  @JsonProperty("update_mask")
  private String updateMask;

  public UpdateCluster setCluster(UpdateClusterResource cluster) {
    this.cluster = cluster;
    return this;
  }

  public UpdateClusterResource getCluster() {
    return cluster;
  }

  public UpdateCluster setClusterId(String clusterId) {
    this.clusterId = clusterId;
    return this;
  }

  public String getClusterId() {
    return clusterId;
  }

  public UpdateCluster setUpdateMask(String updateMask) {
    this.updateMask = updateMask;
    return this;
  }

  public String getUpdateMask() {
    return updateMask;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    UpdateCluster that = (UpdateCluster) o;
    return Objects.equals(cluster, that.cluster)
        && Objects.equals(clusterId, that.clusterId)
        && Objects.equals(updateMask, that.updateMask);
  }

  @Override
  public int hashCode() {
    return Objects.hash(cluster, clusterId, updateMask);
  }

  @Override
  public String toString() {
    return new ToStringer(UpdateCluster.class)
        .add("cluster", cluster)
        .add("clusterId", clusterId)
        .add("updateMask", updateMask)
        .toString();
  }
}
