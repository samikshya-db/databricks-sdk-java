// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.
package com.databricks.sdk.service.workspace;

import com.databricks.sdk.core.ApiClient;
import com.databricks.sdk.support.Generated;
import java.util.HashMap;
import java.util.Map;

/** Package-local implementation of GitCredentials */
@Generated
class GitCredentialsImpl implements GitCredentialsService {
  private final ApiClient apiClient;

  public GitCredentialsImpl(ApiClient apiClient) {
    this.apiClient = apiClient;
  }

  @Override
  public CreateCredentialsResponse create(CreateCredentialsRequest request) {
    String path = "/api/2.0/git-credentials";
    Map<String, String> headers = new HashMap<>();
    headers.put("Accept", "application/json");
    headers.put("Content-Type", "application/json");
    return apiClient.POST(path, request, CreateCredentialsResponse.class, headers);
  }

  @Override
  public void delete(DeleteCredentialsRequest request) {
    String path = String.format("/api/2.0/git-credentials/%s", request.getCredentialId());
    Map<String, String> headers = new HashMap<>();
    headers.put("Accept", "application/json");
    apiClient.DELETE(path, request, DeleteCredentialsResponse.class, headers);
  }

  @Override
  public GetCredentialsResponse get(GetCredentialsRequest request) {
    String path = String.format("/api/2.0/git-credentials/%s", request.getCredentialId());
    Map<String, String> headers = new HashMap<>();
    headers.put("Accept", "application/json");
    return apiClient.GET(path, request, GetCredentialsResponse.class, headers);
  }

  @Override
  public ListCredentialsResponse list() {
    String path = "/api/2.0/git-credentials";
    Map<String, String> headers = new HashMap<>();
    headers.put("Accept", "application/json");
    return apiClient.GET(path, ListCredentialsResponse.class, headers);
  }

  @Override
  public void update(UpdateCredentialsRequest request) {
    String path = String.format("/api/2.0/git-credentials/%s", request.getCredentialId());
    Map<String, String> headers = new HashMap<>();
    headers.put("Accept", "application/json");
    headers.put("Content-Type", "application/json");
    apiClient.PATCH(path, request, UpdateCredentialsResponse.class, headers);
  }
}
