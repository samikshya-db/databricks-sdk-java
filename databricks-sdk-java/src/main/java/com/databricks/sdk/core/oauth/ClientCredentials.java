package com.databricks.sdk.core.oauth;

import com.databricks.sdk.core.DatabricksException;
import com.databricks.sdk.core.commons.CommonsHttpClient;
import com.databricks.sdk.core.http.HttpClient;



import java.io.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;

import java.io.FileReader;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

import java.util.Date;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.*;

/**
 * An implementation of RefreshableTokenSource implementing the client_credentials OAuth grant type.
 *
 * <p>Using the provided client ID, secret, and token URL, this class makes requests using its
 * HttpClient to fetch OAuth tokens. Additional parameters and scopes can be specified as well. To
 * support all OAuth endpoints, authentication parameters can be passed in the request body or in
 * the Authorization header.
 */
public class ClientCredentials extends RefreshableTokenSource {
  public static class Builder {
    private String clientId;
    private String clientSecret;
    private String tokenUrl;
    private String jwtKeyFile;
    private String jwtKid;
    private String jwtKeyPassphrase;
    private String jwtAlgorithm;

    private HttpClient hc = new CommonsHttpClient(30);
    private Map<String, String> endpointParams = Collections.emptyMap();
    private List<String> scopes = Collections.emptyList();
    private AuthParameterPosition position = AuthParameterPosition.BODY;

    public Builder withClientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    public Builder withClientSecret(String clientSecret) {
      this.clientSecret = clientSecret;
      return this;
    }

    public Builder withTokenUrl(String tokenUrl) {
      this.tokenUrl = tokenUrl;
      return this;
    }

    public Builder withEndpointParameters(Map<String, String> params) {
      this.endpointParams = params;
      return this;
    }

    public Builder withScopes(List<String> scopes) {
      this.scopes = scopes;
      return this;
    }

    public Builder withAuthParameterPosition(AuthParameterPosition position) {
      this.position = position;
      return this;
    }

    public Builder withHttpClient(HttpClient hc) {
      this.hc = hc;
      return this;
    }

    public Builder withJwtAlgorithm(String jwtAlgorithm) {
      this.jwtAlgorithm = jwtAlgorithm;
      return this;
    }

    public Builder withJwtKeyPassphrase(String jwtKeyPassphrase) {
      this.jwtKeyPassphrase = jwtKeyPassphrase;
      return this;
    }

    public Builder withJwtKid(String jwtKid) {
      this.jwtKid = jwtKid;
      return this;
    }

    public Builder withJwtKeyFile(String jwtKeyFile) {
      this.jwtKeyFile = jwtKeyFile;
      return this;
    }

    public ClientCredentials build() {
      Objects.requireNonNull(this.clientId, "clientId must be specified");
      if(this.clientSecret == null){
        Objects.requireNonNull(this.jwtKeyFile, "JWT key file must be specified");
        Objects.requireNonNull(this.jwtKid, "JWT KID must be specified");
        return new ClientCredentials(hc,clientId,jwtKeyFile,jwtKid,jwtKeyPassphrase,jwtAlgorithm,tokenUrl,endpointParams,scopes,position);
      }
      Objects.requireNonNull(this.tokenUrl, "tokenUrl must be specified");
      return new ClientCredentials(
          hc, clientId, clientSecret, tokenUrl, endpointParams, scopes, position);
    }
  }

  private HttpClient hc;
  private String clientId;
  private String clientSecret;
  private String tokenUrl;
  private Map<String, String> endpointParams;
  private List<String> scopes;
  private AuthParameterPosition position;

  private String jwtKeyFile;
  private String jwtKid;
  private String jwtKeyPassphrase;
  private JWSAlgorithm jwtAlgorithm;
  private ClientCredentials(
      HttpClient hc,
      String clientId,
      String clientSecret,
      String tokenUrl,
      Map<String, String> endpointParams,
      List<String> scopes,
      AuthParameterPosition position) {
    this.hc = hc;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.tokenUrl = tokenUrl;
    this.endpointParams = endpointParams;
    this.scopes = scopes;
    this.position = position;
  }
  private ClientCredentials(
          HttpClient hc,
          String clientId,
          String jwtKeyFile,
          String jwtKid,
          String jwtKeyPassphrase,
          String jwtAlgorithm,
          String tokenUrl,
          Map<String, String> endpointParams,
          List<String> scopes,
          AuthParameterPosition position) {
    this.hc = hc;
    this.clientId = clientId;
    this.clientSecret = null;
    this.jwtKeyFile = jwtKeyFile;
    this.jwtKid = jwtKid;
    this.jwtKeyPassphrase = jwtKeyPassphrase;
    if(jwtAlgorithm==null) {
      jwtAlgorithm = "ES256";
    }
    try{
      this.jwtAlgorithm = getECAlgorithm(jwtAlgorithm);
    }catch(UnsupportedOperationException e){
      try{
        this.jwtAlgorithm = getRSAAlgorithm(jwtAlgorithm);
      }catch (Exception ex)
      {
      System.out.println("No algorithm found for private key in JWT! Resorting back to ES256");
        this.jwtAlgorithm = JWSAlgorithm.ES256;
      }
    }
    this.tokenUrl = tokenUrl;
    this.endpointParams = endpointParams;
    this.scopes = scopes;
    this.position = position;
  }


  @Override
  protected Token refresh() {
    Map<String, String> params = new HashMap<>();
    params.put("grant_type", "client_credentials");
    if (scopes != null) {
      params.put("scope", String.join(" ", scopes));
    }
    if(this.clientSecret == null){
      params.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
      params.put("client_assertion", getSerialisedSignedJWT());
    }
    if (endpointParams != null) {
      params.putAll(endpointParams);
    }
    return retrieveToken(hc, clientId, clientSecret, tokenUrl, params, new HashMap<>(), position);
  }

 private String getSerialisedSignedJWT(){
   PrivateKey privateKey = getPrivateKey();
   SignedJWT signedJWT = fetchAccessToken(privateKey);
   return signedJWT.serialize();
 }

  // Determines the appropriate signing algorithm based on key type and requested algorith

  private JWSAlgorithm getECAlgorithm(String jwtAlgorithm){
    switch (jwtAlgorithm) {
        case "ES384":
          return JWSAlgorithm.ES384;
        case "ES512":
          return JWSAlgorithm.ES512;
        case "ES256":
          return JWSAlgorithm.ES256;
        default:
          throw new UnsupportedOperationException("EC Algorithm not supported "+ jwtAlgorithm);
      }
    }

  private JWSAlgorithm getRSAAlgorithm(String jwtAlgorithm) throws Exception {
    switch (jwtAlgorithm) {
      case "RS384":
        return JWSAlgorithm.RS384;
      case "RS512":
        return JWSAlgorithm.RS512;
      case "PS256":
        return JWSAlgorithm.PS256;
      case "PS384":
        return JWSAlgorithm.PS384;
      case "PS512":
        return JWSAlgorithm.PS512;
      case "RS256":
        return JWSAlgorithm.RS256;
      default:
        throw new UnsupportedOperationException("RSA Algorithm not supported "+ jwtAlgorithm);
    }
  }

  private String getActualType(JWSAlgorithm algorithm){
    if (algorithm.equals("RS384") || algorithm.equals("RS512") || algorithm.equals("PS256") || algorithm.equals("PS384") || algorithm.equals("PS512") || algorithm.equals("RS256")) {
      return "SunRsaSign";
    }
    return "SunEC";
  }

  // Retrieves the private key (supports encrypted keys via passphrase)
  private PrivateKey getPrivateKey()  {
  try{
    Security.addProvider(new BouncyCastleProvider());
    Reader reader = new FileReader(jwtKeyFile);
    PEMParser pemParser = new PEMParser(reader);
    Object pemObject = pemParser.readObject();
    pemParser.close();
    String actualType = getActualType(jwtAlgorithm);
    PrivateKeyInfo privateKeyInfo;
    if (jwtKeyPassphrase != null) {
      PKCS8EncryptedPrivateKeyInfo pKCS8EncryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo)pemObject;
      JceOpenSSLPKCS8DecryptorProviderBuilder jceOpenSSLPKCS8DecryptorProviderBuilder = new JceOpenSSLPKCS8DecryptorProviderBuilder();
      jceOpenSSLPKCS8DecryptorProviderBuilder.setProvider("BC");
      InputDecryptorProvider inputDecryptorProvider = jceOpenSSLPKCS8DecryptorProviderBuilder.build(jwtKeyPassphrase.toCharArray());
      privateKeyInfo = pKCS8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(inputDecryptorProvider);
    } else {
      try {
        privateKeyInfo = ((PEMKeyPair)pemObject).getPrivateKeyInfo();
      } catch (ClassCastException classCastException) {
        privateKeyInfo = (PrivateKeyInfo)pemObject;
      }
    }
    JcaPEMKeyConverter jcaPEMKeyConverter = (new JcaPEMKeyConverter()).setProvider(actualType);
    return jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);}
    catch (Exception e){
    return null;
    }
  }

  private SignedJWT fetchAccessToken(PrivateKey privateKey) {
    try {
      // Create RSA signer with the private key
      JWSSigner signer = new RSASSASigner(privateKey);
      Timestamp timestamp = Timestamp.valueOf(LocalDateTime.now());
      // Prepare JWT with claims set
      JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
              .subject(clientId)
              .issuer(clientId)
              .issueTime(timestamp)
              .expirationTime(timestamp)
              .claim("scope", "your_scope") // Additional claims
              .build();

      // Create the JWS header with algorithm RSA256
      JWSHeader header = getJWTHeader();

      // Create the signed JWT
      SignedJWT signedJWT = new SignedJWT(header, claimsSet);

      // Compute the RSA signature
      signedJWT.sign(signer);

      return signedJWT;
    } catch (Exception e) {
      throw new DatabricksException("Error signing the JWT: " + e);
    }
  }
}
