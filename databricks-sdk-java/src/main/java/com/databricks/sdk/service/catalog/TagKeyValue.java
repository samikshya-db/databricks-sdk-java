// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.

package com.databricks.sdk.service.catalog;

import com.databricks.sdk.support.Generated;
import com.databricks.sdk.support.ToStringer;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

@Generated
public class TagKeyValue {
  /** name of the tag */
  @JsonProperty("key")
  private String key;

  /** value of the tag associated with the key, could be optional */
  @JsonProperty("value")
  private String value;

  public TagKeyValue setKey(String key) {
    this.key = key;
    return this;
  }

  public String getKey() {
    return key;
  }

  public TagKeyValue setValue(String value) {
    this.value = value;
    return this;
  }

  public String getValue() {
    return value;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    TagKeyValue that = (TagKeyValue) o;
    return Objects.equals(key, that.key) && Objects.equals(value, that.value);
  }

  @Override
  public int hashCode() {
    return Objects.hash(key, value);
  }

  @Override
  public String toString() {
    return new ToStringer(TagKeyValue.class).add("key", key).add("value", value).toString();
  }
}
