// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.

package com.databricks.sdk.service.mlflow;

import com.fasterxml.jackson.annotation.JsonProperty;

public class UpdateRegistryWebhook {
  /** User-specified description for the webhook. */
  @JsonProperty("description")
  private String description;

  /**
   * Events that can trigger a registry webhook: * `MODEL_VERSION_CREATED`: A new model version was
   * created for the associated model.
   *
   * <p>* `MODEL_VERSION_TRANSITIONED_STAGE`: A model version’s stage was changed.
   *
   * <p>* `TRANSITION_REQUEST_CREATED`: A user requested a model version’s stage be transitioned.
   *
   * <p>* `COMMENT_CREATED`: A user wrote a comment on a registered model.
   *
   * <p>* `REGISTERED_MODEL_CREATED`: A new registered model was created. This event type can only
   * be specified for a registry-wide webhook, which can be created by not specifying a model name
   * in the create request.
   *
   * <p>* `MODEL_VERSION_TAG_SET`: A user set a tag on the model version.
   *
   * <p>* `MODEL_VERSION_TRANSITIONED_TO_STAGING`: A model version was transitioned to staging.
   *
   * <p>* `MODEL_VERSION_TRANSITIONED_TO_PRODUCTION`: A model version was transitioned to
   * production.
   *
   * <p>* `MODEL_VERSION_TRANSITIONED_TO_ARCHIVED`: A model version was archived.
   *
   * <p>* `TRANSITION_REQUEST_TO_STAGING_CREATED`: A user requested a model version be transitioned
   * to staging.
   *
   * <p>* `TRANSITION_REQUEST_TO_PRODUCTION_CREATED`: A user requested a model version be
   * transitioned to production.
   *
   * <p>* `TRANSITION_REQUEST_TO_ARCHIVED_CREATED`: A user requested a model version be archived.
   */
  @JsonProperty("events")
  private java.util.List<RegistryWebhookEvent> events;

  /** */
  @JsonProperty("http_url_spec")
  private HttpUrlSpec httpUrlSpec;

  /** Webhook ID */
  @JsonProperty("id")
  private String id;

  /** */
  @JsonProperty("job_spec")
  private JobSpec jobSpec;

  /** This describes an enum */
  @JsonProperty("status")
  private RegistryWebhookStatus status;

  public UpdateRegistryWebhook setDescription(String description) {
    this.description = description;
    return this;
  }

  public String getDescription() {
    return description;
  }

  public UpdateRegistryWebhook setEvents(java.util.List<RegistryWebhookEvent> events) {
    this.events = events;
    return this;
  }

  public java.util.List<RegistryWebhookEvent> getEvents() {
    return events;
  }

  public UpdateRegistryWebhook setHttpUrlSpec(HttpUrlSpec httpUrlSpec) {
    this.httpUrlSpec = httpUrlSpec;
    return this;
  }

  public HttpUrlSpec getHttpUrlSpec() {
    return httpUrlSpec;
  }

  public UpdateRegistryWebhook setId(String id) {
    this.id = id;
    return this;
  }

  public String getId() {
    return id;
  }

  public UpdateRegistryWebhook setJobSpec(JobSpec jobSpec) {
    this.jobSpec = jobSpec;
    return this;
  }

  public JobSpec getJobSpec() {
    return jobSpec;
  }

  public UpdateRegistryWebhook setStatus(RegistryWebhookStatus status) {
    this.status = status;
    return this;
  }

  public RegistryWebhookStatus getStatus() {
    return status;
  }
}
