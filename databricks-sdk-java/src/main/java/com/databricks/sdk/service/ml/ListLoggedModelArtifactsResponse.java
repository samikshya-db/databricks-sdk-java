// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.

package com.databricks.sdk.service.ml;

import com.databricks.sdk.support.Generated;
import com.databricks.sdk.support.ToStringer;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Collection;
import java.util.Objects;

@Generated
public class ListLoggedModelArtifactsResponse {
  /** File location and metadata for artifacts. */
  @JsonProperty("files")
  private Collection<FileInfo> files;

  /** Token that can be used to retrieve the next page of artifact results */
  @JsonProperty("next_page_token")
  private String nextPageToken;

  /** Root artifact directory for the logged model. */
  @JsonProperty("root_uri")
  private String rootUri;

  public ListLoggedModelArtifactsResponse setFiles(Collection<FileInfo> files) {
    this.files = files;
    return this;
  }

  public Collection<FileInfo> getFiles() {
    return files;
  }

  public ListLoggedModelArtifactsResponse setNextPageToken(String nextPageToken) {
    this.nextPageToken = nextPageToken;
    return this;
  }

  public String getNextPageToken() {
    return nextPageToken;
  }

  public ListLoggedModelArtifactsResponse setRootUri(String rootUri) {
    this.rootUri = rootUri;
    return this;
  }

  public String getRootUri() {
    return rootUri;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    ListLoggedModelArtifactsResponse that = (ListLoggedModelArtifactsResponse) o;
    return Objects.equals(files, that.files)
        && Objects.equals(nextPageToken, that.nextPageToken)
        && Objects.equals(rootUri, that.rootUri);
  }

  @Override
  public int hashCode() {
    return Objects.hash(files, nextPageToken, rootUri);
  }

  @Override
  public String toString() {
    return new ToStringer(ListLoggedModelArtifactsResponse.class)
        .add("files", files)
        .add("nextPageToken", nextPageToken)
        .add("rootUri", rootUri)
        .toString();
  }
}
