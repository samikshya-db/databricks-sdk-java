// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.

package com.databricks.sdk.service.jobs;

import com.databricks.sdk.support.Generated;
import com.databricks.sdk.support.ToStringer;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** Run output was retrieved successfully. */
@Generated
public class RunOutput {
  /** The output of a clean rooms notebook task, if available */
  @JsonProperty("clean_rooms_notebook_output")
  private CleanRoomsNotebookTaskCleanRoomsNotebookTaskOutput cleanRoomsNotebookOutput;

  /** The output of a dashboard task, if available */
  @JsonProperty("dashboard_output")
  private DashboardTaskOutput dashboardOutput;

  /** */
  @JsonProperty("dbt_cloud_output")
  private DbtCloudTaskOutput dbtCloudOutput;

  /** The output of a dbt task, if available. */
  @JsonProperty("dbt_output")
  private DbtOutput dbtOutput;

  /**
   * An error message indicating why a task failed or why output is not available. The message is
   * unstructured, and its exact format is subject to change.
   */
  @JsonProperty("error")
  private String error;

  /** If there was an error executing the run, this field contains any available stack traces. */
  @JsonProperty("error_trace")
  private String errorTrace;

  /** */
  @JsonProperty("info")
  private String info;

  /**
   * The output from tasks that write to standard streams (stdout/stderr) such as spark_jar_task,
   * spark_python_task, python_wheel_task.
   *
   * <p>It's not supported for the notebook_task, pipeline_task or spark_submit_task.
   *
   * <p>Databricks restricts this API to return the last 5 MB of these logs.
   */
  @JsonProperty("logs")
  private String logs;

  /** Whether the logs are truncated. */
  @JsonProperty("logs_truncated")
  private Boolean logsTruncated;

  /** All details of the run except for its output. */
  @JsonProperty("metadata")
  private Run metadata;

  /**
   * The output of a notebook task, if available. A notebook task that terminates (either
   * successfully or with a failure) without calling `dbutils.notebook.exit()` is considered to have
   * an empty output. This field is set but its result value is empty. Databricks restricts this API
   * to return the first 5 MB of the output. To return a larger result, use the [ClusterLogConf]
   * field to configure log storage for the job cluster.
   *
   * <p>[ClusterLogConf]:
   * https://docs.databricks.com/dev-tools/api/latest/clusters.html#clusterlogconf
   */
  @JsonProperty("notebook_output")
  private NotebookOutput notebookOutput;

  /** The output of a run job task, if available */
  @JsonProperty("run_job_output")
  private RunJobOutput runJobOutput;

  /** The output of a SQL task, if available. */
  @JsonProperty("sql_output")
  private SqlOutput sqlOutput;

  public RunOutput setCleanRoomsNotebookOutput(
      CleanRoomsNotebookTaskCleanRoomsNotebookTaskOutput cleanRoomsNotebookOutput) {
    this.cleanRoomsNotebookOutput = cleanRoomsNotebookOutput;
    return this;
  }

  public CleanRoomsNotebookTaskCleanRoomsNotebookTaskOutput getCleanRoomsNotebookOutput() {
    return cleanRoomsNotebookOutput;
  }

  public RunOutput setDashboardOutput(DashboardTaskOutput dashboardOutput) {
    this.dashboardOutput = dashboardOutput;
    return this;
  }

  public DashboardTaskOutput getDashboardOutput() {
    return dashboardOutput;
  }

  public RunOutput setDbtCloudOutput(DbtCloudTaskOutput dbtCloudOutput) {
    this.dbtCloudOutput = dbtCloudOutput;
    return this;
  }

  public DbtCloudTaskOutput getDbtCloudOutput() {
    return dbtCloudOutput;
  }

  public RunOutput setDbtOutput(DbtOutput dbtOutput) {
    this.dbtOutput = dbtOutput;
    return this;
  }

  public DbtOutput getDbtOutput() {
    return dbtOutput;
  }

  public RunOutput setError(String error) {
    this.error = error;
    return this;
  }

  public String getError() {
    return error;
  }

  public RunOutput setErrorTrace(String errorTrace) {
    this.errorTrace = errorTrace;
    return this;
  }

  public String getErrorTrace() {
    return errorTrace;
  }

  public RunOutput setInfo(String info) {
    this.info = info;
    return this;
  }

  public String getInfo() {
    return info;
  }

  public RunOutput setLogs(String logs) {
    this.logs = logs;
    return this;
  }

  public String getLogs() {
    return logs;
  }

  public RunOutput setLogsTruncated(Boolean logsTruncated) {
    this.logsTruncated = logsTruncated;
    return this;
  }

  public Boolean getLogsTruncated() {
    return logsTruncated;
  }

  public RunOutput setMetadata(Run metadata) {
    this.metadata = metadata;
    return this;
  }

  public Run getMetadata() {
    return metadata;
  }

  public RunOutput setNotebookOutput(NotebookOutput notebookOutput) {
    this.notebookOutput = notebookOutput;
    return this;
  }

  public NotebookOutput getNotebookOutput() {
    return notebookOutput;
  }

  public RunOutput setRunJobOutput(RunJobOutput runJobOutput) {
    this.runJobOutput = runJobOutput;
    return this;
  }

  public RunJobOutput getRunJobOutput() {
    return runJobOutput;
  }

  public RunOutput setSqlOutput(SqlOutput sqlOutput) {
    this.sqlOutput = sqlOutput;
    return this;
  }

  public SqlOutput getSqlOutput() {
    return sqlOutput;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    RunOutput that = (RunOutput) o;
    return Objects.equals(cleanRoomsNotebookOutput, that.cleanRoomsNotebookOutput)
        && Objects.equals(dashboardOutput, that.dashboardOutput)
        && Objects.equals(dbtCloudOutput, that.dbtCloudOutput)
        && Objects.equals(dbtOutput, that.dbtOutput)
        && Objects.equals(error, that.error)
        && Objects.equals(errorTrace, that.errorTrace)
        && Objects.equals(info, that.info)
        && Objects.equals(logs, that.logs)
        && Objects.equals(logsTruncated, that.logsTruncated)
        && Objects.equals(metadata, that.metadata)
        && Objects.equals(notebookOutput, that.notebookOutput)
        && Objects.equals(runJobOutput, that.runJobOutput)
        && Objects.equals(sqlOutput, that.sqlOutput);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        cleanRoomsNotebookOutput,
        dashboardOutput,
        dbtCloudOutput,
        dbtOutput,
        error,
        errorTrace,
        info,
        logs,
        logsTruncated,
        metadata,
        notebookOutput,
        runJobOutput,
        sqlOutput);
  }

  @Override
  public String toString() {
    return new ToStringer(RunOutput.class)
        .add("cleanRoomsNotebookOutput", cleanRoomsNotebookOutput)
        .add("dashboardOutput", dashboardOutput)
        .add("dbtCloudOutput", dbtCloudOutput)
        .add("dbtOutput", dbtOutput)
        .add("error", error)
        .add("errorTrace", errorTrace)
        .add("info", info)
        .add("logs", logs)
        .add("logsTruncated", logsTruncated)
        .add("metadata", metadata)
        .add("notebookOutput", notebookOutput)
        .add("runJobOutput", runJobOutput)
        .add("sqlOutput", sqlOutput)
        .toString();
  }
}
