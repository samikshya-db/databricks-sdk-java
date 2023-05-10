package com.databricks.sdk.client.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.databricks.sdk.client.DatabricksConfig;
import com.databricks.sdk.client.DatabricksException;
import com.databricks.sdk.client.FixtureServer;
import com.databricks.sdk.client.commons.CommonsHttpClient;
import java.io.IOException;
import org.junit.jupiter.api.Test;

public class ExternalBrowserCredentialsProviderTest {
  @Test
  void clientAndConsentTest() {
    try (FixtureServer fixtures = new FixtureServer()) {
      fixtures.with(
          "GET /oidc/.well-known/oauth-authorization-server",
          "{\"token_endpoint\": \"token-test-end-point\"}");
      String clientID = "test-client-id";
      DatabricksConfig config =
          new DatabricksConfig()
              .setAuthType("external-browser")
              .setHost(fixtures.getUrl())
              .setClientId(clientID)
              .setHttpClient(new CommonsHttpClient(30));
      config.resolve();

      OAuthClient testClient = new OAuthClient(config);
      assertEquals(testClient.getClientId(), clientID);

      Consent testConsent = testClient.initiateConsent();
      assertEquals(testConsent.getTokenUrl(), "token-test-end-point");
    } catch (IOException e) {
      throw new DatabricksException(e.getMessage());
    }
  }
}
