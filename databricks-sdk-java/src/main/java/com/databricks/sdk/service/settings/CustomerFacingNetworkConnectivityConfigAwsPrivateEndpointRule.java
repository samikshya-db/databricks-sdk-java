// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.

package com.databricks.sdk.service.settings;

import com.databricks.sdk.support.Generated;
import com.databricks.sdk.support.ToStringer;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Collection;
import java.util.Objects;

/**
 * Properties of the new private endpoint rule. Note that for private endpoints towards a VPC
 * endpoint service behind a customer-managed NLB, you must approve the endpoint in AWS console
 * after initialization.
 */
@Generated
public class CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRule {
  /** Databricks account ID. You can find your account ID from the Accounts Console. */
  @JsonProperty("account_id")
  private String accountId;

  /**
   * The current status of this private endpoint. The private endpoint rules are effective only if
   * the connection state is ESTABLISHED. Remember that you must approve new endpoints on your
   * resources in the AWS console before they take effect. The possible values are: - PENDING: The
   * endpoint has been created and pending approval. - ESTABLISHED: The endpoint has been approved
   * and is ready to use in your serverless compute resources. - REJECTED: Connection was rejected
   * by the private link resource owner. - DISCONNECTED: Connection was removed by the private link
   * resource owner, the private endpoint becomes informative and should be deleted for clean-up. -
   * EXPIRED: If the endpoint is created but not approved in 14 days, it is EXPIRED.
   */
  @JsonProperty("connection_state")
  private CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRulePrivateLinkConnectionState
      connectionState;

  /** Time in epoch milliseconds when this object was created. */
  @JsonProperty("creation_time")
  private Long creationTime;

  /** Whether this private endpoint is deactivated. */
  @JsonProperty("deactivated")
  private Boolean deactivated;

  /** Time in epoch milliseconds when this object was deactivated. */
  @JsonProperty("deactivated_at")
  private Long deactivatedAt;

  /**
   * Only used by private endpoints towards a VPC endpoint service for customer-managed VPC endpoint
   * service.
   *
   * <p>The target AWS resource FQDNs accessible via the VPC endpoint service. When updating this
   * field, we perform full update on this field. Please ensure a full list of desired domain_names
   * is provided.
   */
  @JsonProperty("domain_names")
  private Collection<String> domainNames;

  /**
   * Only used by private endpoints towards an AWS S3 service.
   *
   * <p>Update this field to activate/deactivate this private endpoint to allow egress access from
   * serverless compute resources.
   */
  @JsonProperty("enabled")
  private Boolean enabled;

  /**
   * The full target AWS endpoint service name that connects to the destination resources of the
   * private endpoint.
   */
  @JsonProperty("endpoint_service")
  private String endpointService;

  /**
   * The ID of a network connectivity configuration, which is the parent resource of this private
   * endpoint rule object.
   */
  @JsonProperty("network_connectivity_config_id")
  private String networkConnectivityConfigId;

  /**
   * Only used by private endpoints towards AWS S3 service.
   *
   * <p>The globally unique S3 bucket names that will be accessed via the VPC endpoint. The bucket
   * names must be in the same region as the NCC/endpoint service. When updating this field, we
   * perform full update on this field. Please ensure a full list of desired resource_names is
   * provided.
   */
  @JsonProperty("resource_names")
  private Collection<String> resourceNames;

  /** The ID of a private endpoint rule. */
  @JsonProperty("rule_id")
  private String ruleId;

  /** Time in epoch milliseconds when this object was updated. */
  @JsonProperty("updated_time")
  private Long updatedTime;

  /**
   * The AWS VPC endpoint ID. You can use this ID to identify VPC endpoint created by Databricks.
   */
  @JsonProperty("vpc_endpoint_id")
  private String vpcEndpointId;

  public CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRule setAccountId(
      String accountId) {
    this.accountId = accountId;
    return this;
  }

  public String getAccountId() {
    return accountId;
  }

  public CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRule setConnectionState(
      CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRulePrivateLinkConnectionState
          connectionState) {
    this.connectionState = connectionState;
    return this;
  }

  public CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRulePrivateLinkConnectionState
      getConnectionState() {
    return connectionState;
  }

  public CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRule setCreationTime(
      Long creationTime) {
    this.creationTime = creationTime;
    return this;
  }

  public Long getCreationTime() {
    return creationTime;
  }

  public CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRule setDeactivated(
      Boolean deactivated) {
    this.deactivated = deactivated;
    return this;
  }

  public Boolean getDeactivated() {
    return deactivated;
  }

  public CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRule setDeactivatedAt(
      Long deactivatedAt) {
    this.deactivatedAt = deactivatedAt;
    return this;
  }

  public Long getDeactivatedAt() {
    return deactivatedAt;
  }

  public CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRule setDomainNames(
      Collection<String> domainNames) {
    this.domainNames = domainNames;
    return this;
  }

  public Collection<String> getDomainNames() {
    return domainNames;
  }

  public CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRule setEnabled(Boolean enabled) {
    this.enabled = enabled;
    return this;
  }

  public Boolean getEnabled() {
    return enabled;
  }

  public CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRule setEndpointService(
      String endpointService) {
    this.endpointService = endpointService;
    return this;
  }

  public String getEndpointService() {
    return endpointService;
  }

  public CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRule
      setNetworkConnectivityConfigId(String networkConnectivityConfigId) {
    this.networkConnectivityConfigId = networkConnectivityConfigId;
    return this;
  }

  public String getNetworkConnectivityConfigId() {
    return networkConnectivityConfigId;
  }

  public CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRule setResourceNames(
      Collection<String> resourceNames) {
    this.resourceNames = resourceNames;
    return this;
  }

  public Collection<String> getResourceNames() {
    return resourceNames;
  }

  public CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRule setRuleId(String ruleId) {
    this.ruleId = ruleId;
    return this;
  }

  public String getRuleId() {
    return ruleId;
  }

  public CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRule setUpdatedTime(
      Long updatedTime) {
    this.updatedTime = updatedTime;
    return this;
  }

  public Long getUpdatedTime() {
    return updatedTime;
  }

  public CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRule setVpcEndpointId(
      String vpcEndpointId) {
    this.vpcEndpointId = vpcEndpointId;
    return this;
  }

  public String getVpcEndpointId() {
    return vpcEndpointId;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRule that =
        (CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRule) o;
    return Objects.equals(accountId, that.accountId)
        && Objects.equals(connectionState, that.connectionState)
        && Objects.equals(creationTime, that.creationTime)
        && Objects.equals(deactivated, that.deactivated)
        && Objects.equals(deactivatedAt, that.deactivatedAt)
        && Objects.equals(domainNames, that.domainNames)
        && Objects.equals(enabled, that.enabled)
        && Objects.equals(endpointService, that.endpointService)
        && Objects.equals(networkConnectivityConfigId, that.networkConnectivityConfigId)
        && Objects.equals(resourceNames, that.resourceNames)
        && Objects.equals(ruleId, that.ruleId)
        && Objects.equals(updatedTime, that.updatedTime)
        && Objects.equals(vpcEndpointId, that.vpcEndpointId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        accountId,
        connectionState,
        creationTime,
        deactivated,
        deactivatedAt,
        domainNames,
        enabled,
        endpointService,
        networkConnectivityConfigId,
        resourceNames,
        ruleId,
        updatedTime,
        vpcEndpointId);
  }

  @Override
  public String toString() {
    return new ToStringer(CustomerFacingNetworkConnectivityConfigAwsPrivateEndpointRule.class)
        .add("accountId", accountId)
        .add("connectionState", connectionState)
        .add("creationTime", creationTime)
        .add("deactivated", deactivated)
        .add("deactivatedAt", deactivatedAt)
        .add("domainNames", domainNames)
        .add("enabled", enabled)
        .add("endpointService", endpointService)
        .add("networkConnectivityConfigId", networkConnectivityConfigId)
        .add("resourceNames", resourceNames)
        .add("ruleId", ruleId)
        .add("updatedTime", updatedTime)
        .add("vpcEndpointId", vpcEndpointId)
        .toString();
  }
}
