// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.
package com.databricks.sdk.service.oauth2;

import com.databricks.sdk.client.ApiClient;
import org.apache.http.client.methods.*;

/**
 * These APIs enable administrators to manage custom oauth app integrations, which is required for
 * adding/using Custom OAuth App Integration like Tableau Cloud for Databricks in AWS cloud.
 *
 * <p>**Note:** You can only add/use the OAuth custom application integrations when OAuth enrollment
 * status is enabled. For more details see :method:OAuthEnrollment/create
 */
public class CustomAppIntegrationAPI {
  private final CustomAppIntegrationService impl;

  /** Regular-use constructor */
  public CustomAppIntegrationAPI(ApiClient apiClient) {
    impl = new CustomAppIntegrationImpl(apiClient);
  }

  /** Constructor for mocks */
  public CustomAppIntegrationAPI(CustomAppIntegrationService mock) {
    impl = mock;
  }

  /**
   * Create Custom OAuth App Integration.
   *
   * <p>Create Custom OAuth App Integration.
   *
   * <p>You can retrieve the custom oauth app integration via :method:get.
   */
  public CreateCustomAppIntegrationOutput create(CreateCustomAppIntegration request) {
    return impl.create(request);
  }

  /**
   * Delete Custom OAuth App Integration.
   *
   * <p>Delete an existing Custom OAuth App Integration. You can retrieve the custom oauth app
   * integration via :method:get.
   */
  public void delete(DeleteCustomAppIntegrationRequest request) {
    impl.delete(request);
  }

  /**
   * Get OAuth Custom App Integration.
   *
   * <p>Gets the Custom OAuth App Integration for the given integration id.
   */
  public GetCustomAppIntegrationOutput get(GetCustomAppIntegrationRequest request) {
    return impl.get(request);
  }

  /**
   * Get custom oauth app integrations.
   *
   * <p>Get the list of custom oauth app integrations for the specified Databricks Account
   */
  public GetCustomAppIntegrationsOutput list() {
    return impl.list();
  }

  /**
   * Updates Custom OAuth App Integration.
   *
   * <p>Updates an existing custom OAuth App Integration. You can retrieve the custom oauth app
   * integration via :method:get.
   */
  public void update(UpdateCustomAppIntegration request) {
    impl.update(request);
  }

  public CustomAppIntegrationService impl() {
    return impl;
  }
}