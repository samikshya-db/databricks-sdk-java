// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.

package com.databricks.sdk.service.pipelines;

import com.databricks.sdk.support.Generated;
import com.databricks.sdk.support.ToStringer;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

@Generated
public class PipelineLibrary {
  /** The path to a file that defines a pipeline and is stored in the Databricks Repos. */
  @JsonProperty("file")
  private FileLibrary file;

  /**
   * The unified field to include source codes. Each entry can be a notebook path, a file path, or a
   * folder path that ends `/**`. This field cannot be used together with `notebook` or `file`.
   */
  @JsonProperty("glob")
  private PathPattern glob;

  /** URI of the jar to be installed. Currently only DBFS is supported. */
  @JsonProperty("jar")
  private String jar;

  /** Specification of a maven library to be installed. */
  @JsonProperty("maven")
  private com.databricks.sdk.service.compute.MavenLibrary maven;

  /** The path to a notebook that defines a pipeline and is stored in the Databricks workspace. */
  @JsonProperty("notebook")
  private NotebookLibrary notebook;

  /** URI of the whl to be installed. */
  @JsonProperty("whl")
  private String whl;

  public PipelineLibrary setFile(FileLibrary file) {
    this.file = file;
    return this;
  }

  public FileLibrary getFile() {
    return file;
  }

  public PipelineLibrary setGlob(PathPattern glob) {
    this.glob = glob;
    return this;
  }

  public PathPattern getGlob() {
    return glob;
  }

  public PipelineLibrary setJar(String jar) {
    this.jar = jar;
    return this;
  }

  public String getJar() {
    return jar;
  }

  public PipelineLibrary setMaven(com.databricks.sdk.service.compute.MavenLibrary maven) {
    this.maven = maven;
    return this;
  }

  public com.databricks.sdk.service.compute.MavenLibrary getMaven() {
    return maven;
  }

  public PipelineLibrary setNotebook(NotebookLibrary notebook) {
    this.notebook = notebook;
    return this;
  }

  public NotebookLibrary getNotebook() {
    return notebook;
  }

  public PipelineLibrary setWhl(String whl) {
    this.whl = whl;
    return this;
  }

  public String getWhl() {
    return whl;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    PipelineLibrary that = (PipelineLibrary) o;
    return Objects.equals(file, that.file)
        && Objects.equals(glob, that.glob)
        && Objects.equals(jar, that.jar)
        && Objects.equals(maven, that.maven)
        && Objects.equals(notebook, that.notebook)
        && Objects.equals(whl, that.whl);
  }

  @Override
  public int hashCode() {
    return Objects.hash(file, glob, jar, maven, notebook, whl);
  }

  @Override
  public String toString() {
    return new ToStringer(PipelineLibrary.class)
        .add("file", file)
        .add("glob", glob)
        .add("jar", jar)
        .add("maven", maven)
        .add("notebook", notebook)
        .add("whl", whl)
        .toString();
  }
}
