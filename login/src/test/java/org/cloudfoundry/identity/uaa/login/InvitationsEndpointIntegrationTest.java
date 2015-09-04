package org.cloudfoundry.identity.uaa.login;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.http.OAuth2ErrorHandler;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
@OAuth2ContextConfiguration(InvitationsEndpointIntegrationTest.IdentityClient.class)
public class InvitationsEndpointIntegrationTest {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();
    private RestOperations client;
    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);
    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.withTestAccounts(serverRunning, testAccounts);

    @Before
    public void createRestTemplate() throws Exception {
        Assume.assumeTrue(!testAccounts.isProfileActive("vcap"));
        client = serverRunning.getRestTemplate();
        ((RestTemplate)serverRunning.getRestTemplate()).setErrorHandler(new OAuth2ErrorHandler(context.getResource()) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) throws IOException {
            }
        });
    }

    @Test
    public void testInviteUsersSucceeds() throws Exception {
        InvitationRequest invitationRequest = new InvitationRequest("client-id", "redirect.uri");
        invitationRequest.setEmails(Arrays.asList("user1@mail.com", "user2@mail.com"));

        HttpHeaders headers = new HttpHeaders();
        ResponseEntity<Map> result = client.exchange(serverRunning.getUrl("/invitations/new"),
                HttpMethod.POST, new HttpEntity<>(invitationRequest, headers), Map.class);
        assertEquals(HttpStatus.CREATED, result.getStatusCode());
        List<Map<String, String>> invitedUsers = (List<Map<String, String>>) result.getBody().get("invited_users");
        invitedUsers.stream().forEach(iu -> {
            assertNotNull(iu.get("user_id"));
            assertTrue(invitationRequest.getEmails().contains(iu.get("email")));
        });
    }

    static class IdentityClient extends ClientCredentialsResourceDetails {
        public IdentityClient(Object target) {
            InvitationsEndpointIntegrationTest test = (InvitationsEndpointIntegrationTest) target;
            ClientCredentialsResourceDetails resource = test.testAccounts.getClientCredentialsResource(
                    new String[] {"zones.write"}, "identity", "identitysecret");
            setClientId(resource.getClientId());
            setClientSecret(resource.getClientSecret());
            setId(getClientId());
            setAccessTokenUri(test.serverRunning.getAccessTokenUri());
        }
    }

    class InvitationRequest {

        @JsonProperty("client_id")
        private String clientId;
        @JsonProperty("redirect_uri")
        private String redirectUri;
        @JsonProperty("emails")
        private List<String> emails;

        public InvitationRequest(String clientId, String redirectUri) {
            this.clientId = clientId;
            this.redirectUri = redirectUri;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getRedirectUri() {
            return redirectUri;
        }

        public void setRedirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
        }

        public List<String> getEmails() {
            return emails;
        }

        public void setEmails(List<String> emails) {
            this.emails = emails;
        }
    }

}