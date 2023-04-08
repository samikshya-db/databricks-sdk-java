// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.
package com.databricks.sdk.service.pipelines;

import com.databricks.sdk.client.ApiClient;
import org.apache.http.client.methods.*;

/**
 * The Delta Live Tables API allows you to create, edit, delete, start, and view details about
 * pipelines.
 *
 * <p>Delta Live Tables is a framework for building reliable, maintainable, and testable data
 * processing pipelines. You define the transformations to perform on your data, and Delta Live
 * Tables manages task orchestration, cluster management, monitoring, data quality, and error
 * handling.
 *
 * <p>Instead of defining your data pipelines using a series of separate Apache Spark tasks, Delta
 * Live Tables manages how your data is transformed based on a target schema you define for each
 * processing step. You can also enforce data quality with Delta Live Tables expectations.
 * Expectations allow you to define expected data quality and specify how to handle records that
 * fail those expectations.
 */
public class PipelinesAPI {
  private final PipelinesService impl;

  /** Regular-use constructor */
  public PipelinesAPI(ApiClient apiClient) {
    impl = new PipelinesImpl(apiClient);
  }

  /** Constructor for mocks */
  public PipelinesAPI(PipelinesService mock) {
    impl = mock;
  }

  /**
   * Create a pipeline.
   *
   * <p>Creates a new data processing pipeline based on the requested configuration. If successful,
   * this method returns the ID of the new pipeline.
   */
  public CreatePipelineResponse create(CreatePipeline request) {
    return impl.create(request);
  }

  /**
   * Delete a pipeline.
   *
   * <p>Deletes a pipeline.
   */
  public void delete(Delete request) {
    impl.delete(request);
  }

  /** Get a pipeline. */
  public GetPipelineResponse get(Get request) {
    return impl.get(request);
  }

  /**
   * Get a pipeline update.
   *
   * <p>Gets an update from an active pipeline.
   */
  public GetUpdateResponse getUpdate(GetUpdate request) {
    return impl.getUpdate(request);
  }

  /**
   * List pipeline events.
   *
   * <p>Retrieves events for a pipeline.
   */
  public ListPipelineEventsResponse listPipelineEvents(ListPipelineEvents request) {
    return impl.listPipelineEvents(request);
  }

  /**
   * List pipelines.
   *
   * <p>Lists pipelines defined in the Delta Live Tables system.
   */
  public ListPipelinesResponse listPipelines(ListPipelines request) {
    return impl.listPipelines(request);
  }

  /**
   * List pipeline updates.
   *
   * <p>List updates for an active pipeline.
   */
  public ListUpdatesResponse listUpdates(ListUpdates request) {
    return impl.listUpdates(request);
  }

  /**
   * Reset a pipeline.
   *
   * <p>Resets a pipeline.
   */
  public void reset(Reset request) {
    impl.reset(request);
  }

  /**
   * Queue a pipeline update.
   *
   * <p>Starts or queues a pipeline update.
   */
  public StartUpdateResponse startUpdate(StartUpdate request) {
    return impl.startUpdate(request);
  }

  /**
   * Stop a pipeline.
   *
   * <p>Stops a pipeline.
   */
  public void stop(Stop request) {
    impl.stop(request);
  }

  /**
   * Edit a pipeline.
   *
   * <p>Updates a pipeline with the supplied configuration.
   */
  public void update(EditPipeline request) {
    impl.update(request);
  }

  public PipelinesService impl() {
    return impl;
  }
}
