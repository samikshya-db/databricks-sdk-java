// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.

package com.databricks.sdk.service.jobs;

import com.databricks.sdk.support.Generated;
import com.databricks.sdk.support.ToStringer;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Collection;
import java.util.Objects;

/** Run was exported successfully. */
@Generated
public class ExportRunOutput {
  /**
   * The exported content in HTML format (one for every view item). To extract the HTML notebook
   * from the JSON response, download and run this [Python script].
   *
   * <p>[Python script]: https://docs.databricks.com/en/_static/examples/extract.py
   */
  @JsonProperty("views")
  private Collection<ViewItem> views;

  public ExportRunOutput setViews(Collection<ViewItem> views) {
    this.views = views;
    return this;
  }

  public Collection<ViewItem> getViews() {
    return views;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    ExportRunOutput that = (ExportRunOutput) o;
    return Objects.equals(views, that.views);
  }

  @Override
  public int hashCode() {
    return Objects.hash(views);
  }

  @Override
  public String toString() {
    return new ToStringer(ExportRunOutput.class).add("views", views).toString();
  }
}
