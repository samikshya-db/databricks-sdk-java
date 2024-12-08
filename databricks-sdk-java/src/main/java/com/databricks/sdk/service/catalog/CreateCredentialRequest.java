// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.

package com.databricks.sdk.service.catalog;

import com.databricks.sdk.support.Generated;
import com.databricks.sdk.support.ToStringer;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

@Generated
public class CreateCredentialRequest {
  /** The AWS IAM role configuration */
  @JsonProperty("aws_iam_role")
  private AwsIamRole awsIamRole;

  /** The Azure managed identity configuration. */
  @JsonProperty("azure_managed_identity")
  private AzureManagedIdentity azureManagedIdentity;

  /** Comment associated with the credential. */
  @JsonProperty("comment")
  private String comment;

  /**
   * The credential name. The name must be unique among storage and service credentials within the
   * metastore.
   */
  @JsonProperty("name")
  private String name;

  /** Indicates the purpose of the credential. */
  @JsonProperty("purpose")
  private CredentialPurpose purpose;

  /**
   * Optional. Supplying true to this argument skips validation of the created set of credentials.
   */
  @JsonProperty("skip_validation")
  private Boolean skipValidation;

  public CreateCredentialRequest setAwsIamRole(AwsIamRole awsIamRole) {
    this.awsIamRole = awsIamRole;
    return this;
  }

  public AwsIamRole getAwsIamRole() {
    return awsIamRole;
  }

  public CreateCredentialRequest setAzureManagedIdentity(
      AzureManagedIdentity azureManagedIdentity) {
    this.azureManagedIdentity = azureManagedIdentity;
    return this;
  }

  public AzureManagedIdentity getAzureManagedIdentity() {
    return azureManagedIdentity;
  }

  public CreateCredentialRequest setComment(String comment) {
    this.comment = comment;
    return this;
  }

  public String getComment() {
    return comment;
  }

  public CreateCredentialRequest setName(String name) {
    this.name = name;
    return this;
  }

  public String getName() {
    return name;
  }

  public CreateCredentialRequest setPurpose(CredentialPurpose purpose) {
    this.purpose = purpose;
    return this;
  }

  public CredentialPurpose getPurpose() {
    return purpose;
  }

  public CreateCredentialRequest setSkipValidation(Boolean skipValidation) {
    this.skipValidation = skipValidation;
    return this;
  }

  public Boolean getSkipValidation() {
    return skipValidation;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    CreateCredentialRequest that = (CreateCredentialRequest) o;
    return Objects.equals(awsIamRole, that.awsIamRole)
        && Objects.equals(azureManagedIdentity, that.azureManagedIdentity)
        && Objects.equals(comment, that.comment)
        && Objects.equals(name, that.name)
        && Objects.equals(purpose, that.purpose)
        && Objects.equals(skipValidation, that.skipValidation);
  }

  @Override
  public int hashCode() {
    return Objects.hash(awsIamRole, azureManagedIdentity, comment, name, purpose, skipValidation);
  }

  @Override
  public String toString() {
    return new ToStringer(CreateCredentialRequest.class)
        .add("awsIamRole", awsIamRole)
        .add("azureManagedIdentity", azureManagedIdentity)
        .add("comment", comment)
        .add("name", name)
        .add("purpose", purpose)
        .add("skipValidation", skipValidation)
        .toString();
  }
}
