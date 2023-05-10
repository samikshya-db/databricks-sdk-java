// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.
package com.databricks.sdk.service.compute;

import com.databricks.sdk.core.ApiClient;
import com.databricks.sdk.support.Generated;

/** Package-local implementation of GlobalInitScripts */
@Generated
class GlobalInitScriptsImpl implements GlobalInitScriptsService {
  private final ApiClient apiClient;

  public GlobalInitScriptsImpl(ApiClient apiClient) {
    this.apiClient = apiClient;
  }

  @Override
  public CreateResponse create(GlobalInitScriptCreateRequest request) {
    String path = "/api/2.0/global-init-scripts";
    return apiClient.POST(path, request, CreateResponse.class);
  }

  @Override
  public void delete(DeleteGlobalInitScriptRequest request) {
    String path = String.format("/api/2.0/global-init-scripts/%s", request.getScriptId());
    apiClient.DELETE(path, request, Void.class);
  }

  @Override
  public GlobalInitScriptDetailsWithContent get(GetGlobalInitScriptRequest request) {
    String path = String.format("/api/2.0/global-init-scripts/%s", request.getScriptId());
    return apiClient.GET(path, request, GlobalInitScriptDetailsWithContent.class);
  }

  @Override
  public ListGlobalInitScriptsResponse list() {
    String path = "/api/2.0/global-init-scripts";
    return apiClient.GET(path, ListGlobalInitScriptsResponse.class);
  }

  @Override
  public void update(GlobalInitScriptUpdateRequest request) {
    String path = String.format("/api/2.0/global-init-scripts/%s", request.getScriptId());
    apiClient.PATCH(path, request, Void.class);
  }
}
