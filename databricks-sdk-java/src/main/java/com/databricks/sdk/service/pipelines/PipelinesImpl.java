// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.
package com.databricks.sdk.service.pipelines;

import com.databricks.sdk.core.ApiClient;
import com.databricks.sdk.support.Generated;

/** Package-local implementation of Pipelines */
@Generated
class PipelinesImpl implements PipelinesService {
  private final ApiClient apiClient;

  public PipelinesImpl(ApiClient apiClient) {
    this.apiClient = apiClient;
  }

  @Override
  public CreatePipelineResponse create(CreatePipeline request) {
    String path = "/api/2.0/pipelines";
    return apiClient.POST(path, request, CreatePipelineResponse.class);
  }

  @Override
  public void delete(DeletePipelineRequest request) {
    String path = String.format("/api/2.0/pipelines/%s", request.getPipelineId());
    apiClient.DELETE(path, request, Void.class);
  }

  @Override
  public GetPipelineResponse get(GetPipelineRequest request) {
    String path = String.format("/api/2.0/pipelines/%s", request.getPipelineId());
    return apiClient.GET(path, request, GetPipelineResponse.class, "application/json");
  }

  @Override
  public GetPipelinePermissionLevelsResponse getPipelinePermissionLevels(
      GetPipelinePermissionLevelsRequest request) {
    String path =
        String.format(
            "/api/2.0/permissions/pipelines/%s/permissionLevels", request.getPipelineId());
    return apiClient.GET(
        path, request, GetPipelinePermissionLevelsResponse.class, "application/json");
  }

  @Override
  public PipelinePermissions getPipelinePermissions(GetPipelinePermissionsRequest request) {
    String path = String.format("/api/2.0/permissions/pipelines/%s", request.getPipelineId());
    return apiClient.GET(path, request, PipelinePermissions.class, "application/json");
  }

  @Override
  public GetUpdateResponse getUpdate(GetUpdateRequest request) {
    String path =
        String.format(
            "/api/2.0/pipelines/%s/updates/%s", request.getPipelineId(), request.getUpdateId());
    return apiClient.GET(path, request, GetUpdateResponse.class, "application/json");
  }

  @Override
  public ListPipelineEventsResponse listPipelineEvents(ListPipelineEventsRequest request) {
    String path = String.format("/api/2.0/pipelines/%s/events", request.getPipelineId());
    return apiClient.GET(path, request, ListPipelineEventsResponse.class, "application/json");
  }

  @Override
  public ListPipelinesResponse listPipelines(ListPipelinesRequest request) {
    String path = "/api/2.0/pipelines";
    return apiClient.GET(path, request, ListPipelinesResponse.class, "application/json");
  }

  @Override
  public ListUpdatesResponse listUpdates(ListUpdatesRequest request) {
    String path = String.format("/api/2.0/pipelines/%s/updates", request.getPipelineId());
    return apiClient.GET(path, request, ListUpdatesResponse.class, "application/json");
  }

  @Override
  public void reset(ResetRequest request) {
    String path = String.format("/api/2.0/pipelines/%s/reset", request.getPipelineId());
    apiClient.POST(path, request, Void.class);
  }

  @Override
  public PipelinePermissions setPipelinePermissions(PipelinePermissionsRequest request) {
    String path = String.format("/api/2.0/permissions/pipelines/%s", request.getPipelineId());
    return apiClient.PUT(path, request, PipelinePermissions.class);
  }

  @Override
  public StartUpdateResponse startUpdate(StartUpdate request) {
    String path = String.format("/api/2.0/pipelines/%s/updates", request.getPipelineId());
    return apiClient.POST(path, request, StartUpdateResponse.class);
  }

  @Override
  public void stop(StopRequest request) {
    String path = String.format("/api/2.0/pipelines/%s/stop", request.getPipelineId());
    apiClient.POST(path, request, Void.class);
  }

  @Override
  public void update(EditPipeline request) {
    String path = String.format("/api/2.0/pipelines/%s", request.getPipelineId());
    apiClient.PUT(path, request, Void.class);
  }

  @Override
  public PipelinePermissions updatePipelinePermissions(PipelinePermissionsRequest request) {
    String path = String.format("/api/2.0/permissions/pipelines/%s", request.getPipelineId());
    return apiClient.PATCH(path, request, PipelinePermissions.class);
  }
}
