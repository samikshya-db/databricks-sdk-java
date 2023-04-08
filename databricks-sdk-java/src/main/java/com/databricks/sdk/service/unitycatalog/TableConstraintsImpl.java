// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.
package com.databricks.sdk.service.unitycatalog;

import com.databricks.sdk.client.ApiClient;
import org.apache.http.client.methods.*;

/** Package-local implementation of TableConstraints */
class TableConstraintsImpl implements TableConstraintsService {
  private final ApiClient apiClient;

  public TableConstraintsImpl(ApiClient apiClient) {
    this.apiClient = apiClient;
  }

  @Override
  public TableConstraint create(CreateTableConstraint request) {
    String path = "/api/2.1/unity-catalog/constraints";
    return apiClient.POST(path, request, TableConstraint.class);
  }

  @Override
  public void delete(DeleteTableConstraintRequest request) {
    String path = String.format("/api/2.1/unity-catalog/constraints/%s", request.getFullName());
    apiClient.DELETE(path, request, Void.class);
  }
}
