package com.databricks.sdk.core.oauth;

import com.databricks.sdk.core.DatabricksException;
import com.databricks.sdk.core.utils.Environment;
import com.google.common.base.Strings;

/** Implementation of {@link IDTokenSource} that reads the ID token from an environment variable. */
public class EnvVarIDTokenSource implements IDTokenSource {
  /* The name of the environment variable to read the ID token from. */
  private final String envVarName;
  /* The environment to read variables from. */
  private final Environment env;

  /**
   * Creates a new EnvVarIDTokenSource that reads from the specified environment variable.
   *
   * @param envVarName The name of the environment variable to read the ID token from.
   * @param env The environment to read variables from.
   */
  public EnvVarIDTokenSource(String envVarName, Environment env) {
    this.envVarName = envVarName;
    this.env = env;
  }

  /**
   * Retrieves an ID Token from the environment variable.
   *
   * @param audience The intended recipient of the ID Token (unused in this implementation).
   * @return An {@link IDToken} containing the token value from the environment variable.
   * @throws IllegalArgumentException if the environment variable name is null or empty.
   * @throws DatabricksException if the environment variable is not set or is empty.
   */
  @Override
  public IDToken getIDToken(String audience) {
    if (Strings.isNullOrEmpty(envVarName)) {
      throw new IllegalArgumentException("Environment variable name cannot be null or empty");
    }

    try {
      String token = env.get(envVarName);
      return new IDToken(token);
    } catch (IllegalArgumentException e) {
      throw new DatabricksException(
          String.format("Received empty ID token from environment variable %s", envVarName), e);
    }
  }
}
