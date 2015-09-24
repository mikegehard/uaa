package org.cloudfoundry.identity.uaa.invitations;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.identity.uaa.login.EmailService;
import org.cloudfoundry.identity.uaa.login.util.FakeJavaMailSender;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.ClientUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import javax.mail.Message;
import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.util.ClientUtils.createScimClient;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.cloudfoundry.identity.uaa.login.util.FakeJavaMailSender.MimeMessageWrapper;

public class InvitationsEndpointMockMvcTests extends InjectedMockContextTest {

    private String scimInviteToken;
    private TestClient testClient;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private String clientId;
    private String clientSecret;
    private String adminToken;
    private String authorities;
    private FakeJavaMailSender fakeJavaMailSender = new FakeJavaMailSender();
    private JavaMailSender originalSender;

    @Before
    public void setUp() throws Exception {
        testClient = new TestClient(getMockMvc());
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "clients.read clients.write clients.secret scim.read scim.write");
        clientId = generator.generate().toLowerCase();
        clientSecret = generator.generate().toLowerCase();
        authorities = "scim.read,scim.invite";
        createScimClient(this.getMockMvc(), adminToken, clientId, clientSecret, "oauth", "scim.read,scim.invite", Arrays.asList(new ClientUtils.GrantType[] {ClientUtils.GrantType.client_credentials, ClientUtils.GrantType.password}), authorities);
        scimInviteToken = testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret,"scim.read scim.invite");
    }

    @Before
    public void setUpFakeMailServer() throws Exception {
        originalSender = getWebApplicationContext().getBean("emailService", EmailService.class).getMailSender();
        getWebApplicationContext().getBean("emailService", EmailService.class).setMailSender(fakeJavaMailSender);
    }

    @After
    public void restoreMailServer() throws Exception {
        getWebApplicationContext().getBean("emailService", EmailService.class).setMailSender(originalSender);
    }

    @Test
    public void test_Invitations_Accept_Get_Security() throws Exception {
        getWebApplicationContext().getBean(JdbcTemplate.class).update("DELETE FROM expiring_code_store");
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(getWebApplicationContext());
        String email = generator.generate()+"@test.org";

        String userToken = MockMvcUtils.utils().getScimInviteUserToken(getMockMvc(), clientId, clientSecret);
        sendRequestWithToken(userToken, "user1@example.com");

        String code = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("SELECT code FROM expiring_code_store", String.class);
        assertNotNull("Invite Code Must be Present",code);

        MockHttpServletRequestBuilder accept = get("/invitations/accept")
            .param("code", code);

        getMockMvc().perform(accept)
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("<form method=\"post\" novalidate=\"novalidate\" action=\"/invitations/accept.do\">")));
    }


    @Test
    public void testInviteUserWithClientCredentials() throws Exception {
        String email = "user1@example.com";
        sendRequestWithToken(scimInviteToken, email);
    }

    @Test
    public void testInviteMultipleUsersWithClientCredentials() throws Exception {
        String[] emails = new String[] {"user1@example.com", "user2@example.com"};
        sendRequestWithToken(scimInviteToken, emails);
    }

    @Test
    public void testInviteUserWithUserCredentials() throws Exception {
        String userToken = MockMvcUtils.utils().getScimInviteUserToken(getMockMvc(), clientId, clientSecret);
        sendRequestWithToken(userToken, "user1@example.com");
    }

    // TODO: Test multiple invited users, existing verified users, existing unverified users, null emails

    private void sendRequestWithToken(String token, String...emails) throws Exception {
        InvitationsRequest invitations = new InvitationsRequest(emails);

        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
        byte[] requestBody = objectMapper.writeValueAsBytes(invitations);

        MvcResult result = getMockMvc().perform(post("/invite_users")
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, "example.com")
            .header("Authorization", "Bearer " + token)
            .contentType(APPLICATION_JSON)
            .content(requestBody))
            .andExpect(status().isOk())
            .andReturn();

        InvitationsResponse response = objectMapper.readValue(result.getResponse().getContentAsString(), InvitationsResponse.class);
        assertThat(response.getNewInvites().size(), is(emails.length));
        assertThat(response.getAlreadyInvited().size(), is(0));
        assertThat(response.getFailedInvites().size(), is(0));

        assertEquals(emails.length, fakeJavaMailSender.getSentMessages().size());
        for (int i=0; i < emails.length; i++) {
            MimeMessageWrapper mimeMessageWrapper = fakeJavaMailSender.getSentMessages().get(i);
            assertEquals(1, mimeMessageWrapper.getRecipients(Message.RecipientType.TO).size());
            assertEquals(emails[i], mimeMessageWrapper.getRecipients(Message.RecipientType.TO).get(0).toString());
        }
    }

}
