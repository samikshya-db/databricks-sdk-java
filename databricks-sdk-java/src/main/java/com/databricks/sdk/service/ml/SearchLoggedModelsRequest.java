// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.

package com.databricks.sdk.service.ml;

import com.databricks.sdk.support.Generated;
import com.databricks.sdk.support.ToStringer;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Collection;
import java.util.Objects;

@Generated
public class SearchLoggedModelsRequest {
  /**
   * List of datasets on which to apply the metrics filter clauses. For example, a filter with
   * `metrics.accuracy > 0.9` and dataset info with name "test_dataset" means we will return all
   * logged models with accuracy > 0.9 on the test_dataset. Metric values from ANY dataset matching
   * the criteria are considered. If no datasets are specified, then metrics across all datasets are
   * considered in the filter.
   */
  @JsonProperty("datasets")
  private Collection<SearchLoggedModelsDataset> datasets;

  /** The IDs of the experiments in which to search for logged models. */
  @JsonProperty("experiment_ids")
  private Collection<String> experimentIds;

  /**
   * A filter expression over logged model info and data that allows returning a subset of logged
   * models. The syntax is a subset of SQL that supports AND'ing together binary operations.
   *
   * <p>Example: ``params.alpha < 0.3 AND metrics.accuracy > 0.9``.
   */
  @JsonProperty("filter")
  private String filter;

  /** The maximum number of Logged Models to return. The maximum limit is 50. */
  @JsonProperty("max_results")
  private Long maxResults;

  /** The list of columns for ordering the results, with additional fields for sorting criteria. */
  @JsonProperty("order_by")
  private Collection<SearchLoggedModelsOrderBy> orderBy;

  /** The token indicating the page of logged models to fetch. */
  @JsonProperty("page_token")
  private String pageToken;

  public SearchLoggedModelsRequest setDatasets(Collection<SearchLoggedModelsDataset> datasets) {
    this.datasets = datasets;
    return this;
  }

  public Collection<SearchLoggedModelsDataset> getDatasets() {
    return datasets;
  }

  public SearchLoggedModelsRequest setExperimentIds(Collection<String> experimentIds) {
    this.experimentIds = experimentIds;
    return this;
  }

  public Collection<String> getExperimentIds() {
    return experimentIds;
  }

  public SearchLoggedModelsRequest setFilter(String filter) {
    this.filter = filter;
    return this;
  }

  public String getFilter() {
    return filter;
  }

  public SearchLoggedModelsRequest setMaxResults(Long maxResults) {
    this.maxResults = maxResults;
    return this;
  }

  public Long getMaxResults() {
    return maxResults;
  }

  public SearchLoggedModelsRequest setOrderBy(Collection<SearchLoggedModelsOrderBy> orderBy) {
    this.orderBy = orderBy;
    return this;
  }

  public Collection<SearchLoggedModelsOrderBy> getOrderBy() {
    return orderBy;
  }

  public SearchLoggedModelsRequest setPageToken(String pageToken) {
    this.pageToken = pageToken;
    return this;
  }

  public String getPageToken() {
    return pageToken;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    SearchLoggedModelsRequest that = (SearchLoggedModelsRequest) o;
    return Objects.equals(datasets, that.datasets)
        && Objects.equals(experimentIds, that.experimentIds)
        && Objects.equals(filter, that.filter)
        && Objects.equals(maxResults, that.maxResults)
        && Objects.equals(orderBy, that.orderBy)
        && Objects.equals(pageToken, that.pageToken);
  }

  @Override
  public int hashCode() {
    return Objects.hash(datasets, experimentIds, filter, maxResults, orderBy, pageToken);
  }

  @Override
  public String toString() {
    return new ToStringer(SearchLoggedModelsRequest.class)
        .add("datasets", datasets)
        .add("experimentIds", experimentIds)
        .add("filter", filter)
        .add("maxResults", maxResults)
        .add("orderBy", orderBy)
        .add("pageToken", pageToken)
        .toString();
  }
}
