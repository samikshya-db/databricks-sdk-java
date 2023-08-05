// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.
package com.databricks.sdk.service.catalog;

import com.databricks.sdk.core.ApiClient;
import com.databricks.sdk.support.Generated;

/** Package-local implementation of StorageCredentials */
@Generated
class StorageCredentialsImpl implements StorageCredentialsService {
  private final ApiClient apiClient;

  public StorageCredentialsImpl(ApiClient apiClient) {
    this.apiClient = apiClient;
  }

  @Override
  public StorageCredentialInfo create(CreateStorageCredential request) {
    String path = "/api/2.1/unity-catalog/storage-credentials";
    return apiClient.POST(path, request, StorageCredentialInfo.class);
  }

  @Override
  public void delete(DeleteStorageCredentialRequest request) {
    String path = String.format("/api/2.1/unity-catalog/storage-credentials/%s", request.getName());
    apiClient.DELETE(path, request, Void.class);
  }

  @Override
  public StorageCredentialInfo get(GetStorageCredentialRequest request) {
    String path = String.format("/api/2.1/unity-catalog/storage-credentials/%s", request.getName());
    return apiClient.GET(path, request, StorageCredentialInfo.class, "application/json");
  }

  @Override
  public ListStorageCredentialsResponse list() {
    String path = "/api/2.1/unity-catalog/storage-credentials";
    return apiClient.GET(path, ListStorageCredentialsResponse.class, "application/json");
  }

  @Override
  public StorageCredentialInfo update(UpdateStorageCredential request) {
    String path = String.format("/api/2.1/unity-catalog/storage-credentials/%s", request.getName());
    return apiClient.PATCH(path, request, StorageCredentialInfo.class);
  }

  @Override
  public ValidateStorageCredentialResponse validate(ValidateStorageCredential request) {
    String path = "/api/2.1/unity-catalog/validate-storage-credentials";
    return apiClient.POST(path, request, ValidateStorageCredentialResponse.class);
  }
}
