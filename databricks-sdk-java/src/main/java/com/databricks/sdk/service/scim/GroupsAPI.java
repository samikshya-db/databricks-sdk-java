// Code generated from OpenAPI specs by Databricks SDK Generator. DO NOT EDIT.
package com.databricks.sdk.service.scim;

import com.databricks.sdk.client.ApiClient;
import org.apache.http.client.methods.*;

/**
 * Groups simplify identity management, making it easier to assign access to Databricks Workspace,
 * data, and other securable objects.
 *
 * <p>It is best practice to assign access to workspaces and access-control policies in Unity
 * Catalog to groups, instead of to users individually. All Databricks Workspace identities can be
 * assigned as members of groups, and members inherit permissions that are assigned to their group.
 */
public class GroupsAPI {
  private final GroupsService impl;

  /** Regular-use constructor */
  public GroupsAPI(ApiClient apiClient) {
    impl = new GroupsImpl(apiClient);
  }

  /** Constructor for mocks */
  public GroupsAPI(GroupsService mock) {
    impl = mock;
  }

  /**
   * Create a new group.
   *
   * <p>Creates a group in the Databricks Workspace with a unique name, using the supplied group
   * details.
   */
  public Group create(Group request) {
    return impl.create(request);
  }

  /**
   * Delete a group.
   *
   * <p>Deletes a group from the Databricks Workspace.
   */
  public void delete(DeleteGroupRequest request) {
    impl.delete(request);
  }

  /**
   * Get group details.
   *
   * <p>Gets the information for a specific group in the Databricks Workspace.
   */
  public Group get(GetGroupRequest request) {
    return impl.get(request);
  }

  /**
   * List group details.
   *
   * <p>Gets all details of the groups associated with the Databricks Workspace.
   */
  public ListGroupsResponse list(ListGroupsRequest request) {
    return impl.list(request);
  }

  /**
   * Update group details.
   *
   * <p>Partially updates the details of a group.
   */
  public void patch(PartialUpdate request) {
    impl.patch(request);
  }

  /**
   * Replace a group.
   *
   * <p>Updates the details of a group by replacing the entire group entity.
   */
  public void update(Group request) {
    impl.update(request);
  }

  public GroupsService impl() {
    return impl;
  }
}
