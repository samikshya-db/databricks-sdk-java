// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.

package com.databricks.sdk.service.jobs;

import com.databricks.sdk.support.Generated;

/**
 * The type of a run. * `JOB_RUN`: Normal job run. A run created with :method:jobs/runNow. *
 * `WORKFLOW_RUN`: Workflow run. A run created with [dbutils.notebook.run]. * `SUBMIT_RUN`: Submit
 * run. A run created with :method:jobs/submit.
 *
 * <p>[dbutils.notebook.run]:
 * https://docs.databricks.com/dev-tools/databricks-utils.html#dbutils-workflow
 */
@Generated
public enum RunType {
  JOB_RUN, // Normal job run. A run created with :method:jobs/runNow.
  SUBMIT_RUN, // Submit run. A run created with :method:jobs/submit.
  WORKFLOW_RUN, // Workflow run. A run created with [dbutils.notebook.run].
  //
  // [dbutils.notebook.run]:
  // https://docs.databricks.com/dev-tools/databricks-utils.html#dbutils-workflow

}
