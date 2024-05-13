package dk.rmgroup.keycloak.authentication.authenticators.resetcred;

import org.keycloak.Config;
import org.keycloak.authentication.*;
import org.keycloak.authentication.actiontoken.resetcred.ResetCredentialsActionToken;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import java.net.HttpURLConnection;
import java.net.URI;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.util.*;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.util.stream.Collectors;

import dk.rmgroup.keycloak.KeycloakSmsConstants;

import org.jboss.logging.Logger;

public class ResetCredentialSms implements Authenticator, AuthenticatorFactory {
  private static final Logger logger = Logger.getLogger(ResetCredentialSms.class);

  public static final String PROVIDER_ID = "reset-credential-sms";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
    String username = authenticationSession.getAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME);

    // we don't want people guessing usernames, so if there was a problem obtaining
    // the user, the user will be null.
    // just reset login for with a success message
    if (user == null) {
      context.forkWithSuccessMessage(new FormMessage(KeycloakSmsConstants.MESSAGE_SMS_SEND));
      return;
    }

    String actionTokenUserId = authenticationSession.getAuthNote(DefaultActionTokenKey.ACTION_TOKEN_USER_ID);
    if (actionTokenUserId != null && Objects.equals(user.getId(), actionTokenUserId)) {
      logger.debugf(
          "Forget-password triggered when reauthenticating user after authentication via action token. Skipping "
              + PROVIDER_ID + " screen and using user '%s' ",
          user.getUsername());
      context.success();
      return;
    }

    String mobileNumber = user.getFirstAttribute(KeycloakSmsConstants.ATTR_MOBILE);

    EventBuilder event = context.getEvent();
    // we don't want people guessing usernames, so if there is a problem, just
    // continuously challenge
    if (mobileNumber == null || mobileNumber.trim().length() == 0) {
      event.user(user)
          .detail(Details.USERNAME, username)
          .error(KeycloakSmsConstants.INVALID_MOBILE);

      context.forkWithSuccessMessage(new FormMessage(KeycloakSmsConstants.MESSAGE_SMS_SEND));
      return;
    }

    int validityInSecs = context.getRealm()
        .getActionTokenGeneratedByUserLifespan(ResetCredentialsActionToken.TOKEN_TYPE);
    int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;

    // We send the secret in the email in a link as a query param.
    String authSessionEncodedId = AuthenticationSessionCompoundId.fromAuthSession(authenticationSession).getEncodedId();
    ResetCredentialsActionToken token = new ResetCredentialsActionToken(user.getId(), user.getEmail(),
        absoluteExpirationInSecs, authSessionEncodedId, authenticationSession.getClient().getClientId());
    String link = UriBuilder
        .fromUri(
            context.getActionTokenUrl(token.serialize(context.getSession(), context.getRealm(), context.getUriInfo())))
        .build()
        .toString();

    KeycloakSession session = context.getSession();

    Locale locale = session.getContext().resolveLocale(user);

    try {
      Properties messages = session.theme().getTheme(Theme.Type.EMAIL).getMessages(locale);
      String smsTextMessage = new MessageFormat(messages.getProperty("smsTextMessage"), locale)
          .format(new String[] { link });
      AuthenticatorConfigModel config = context.getAuthenticatorConfig();

      URL url = URI.create(getConfigString(config, KeycloakSmsConstants.CONF_SMS_URL)).toURL();

      HttpURLConnection connection = (HttpURLConnection) url.openConnection();
      connection.setRequestMethod("POST");
      connection.setRequestProperty("Content-Type", "application/json");
      connection.setRequestProperty("Accept", "application/json");
      connection.setDoOutput(true);
      OutputStream os = connection.getOutputStream();
      OutputStreamWriter osw = new OutputStreamWriter(os, "UTF-8");

      String inputText = "{\"" + getConfigString(config, KeycloakSmsConstants.CONF_SMS_FIELD_FROM) + "\": \""
          + getConfigString(config, KeycloakSmsConstants.CONF_SMS_FROM) + "\", \""
          + getConfigString(config, KeycloakSmsConstants.CONF_SMS_FIELD_TO)
          + "\": \"" + mobileNumber + "\", \"" + getConfigString(config, KeycloakSmsConstants.CONF_SMS_FIELD_TEXT)
          + "\": \""
          + smsTextMessage.replace("\n", "\\n")
          + "\", \"" + getConfigString(config, KeycloakSmsConstants.CONF_SMS_FIELD_API_KEY)
          + "\": \"" + getConfigString(config, KeycloakSmsConstants.CONF_SMS_API_KEY) + "\", \""
          + getConfigString(config, KeycloakSmsConstants.CONF_SMS_FIELD_API_SECRET) + "\": \""
          + getConfigString(config, KeycloakSmsConstants.CONF_SMS_API_SECRET) + "\"}";

      osw.write(inputText);
      osw.flush();
      osw.close();
      os.close();
      connection.connect();

      String responseString;

      try (InputStream responseStream = connection.getInputStream()) {
        responseString = new BufferedReader(
            new InputStreamReader(responseStream, StandardCharsets.UTF_8))
            .lines()
            .collect(Collectors.joining("\n"));
      } catch (Exception e) {
        logger.error("Failed to get response string", e);
        responseString = "Failed to get response string";
      }

      int statusCode = connection.getResponseCode();

      if (statusCode == 200) {
        event.clone().event(EventType.SEND_RESET_PASSWORD)
            .user(user)
            .detail(Details.USERNAME, username)
            .detail(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber)
            .detail("status_code", String.valueOf(statusCode))
            .detail("response", responseString)
            .detail(Details.CODE_ID, authenticationSession.getParentSession().getId()).success();

        context.forkWithSuccessMessage(new FormMessage(KeycloakSmsConstants.MESSAGE_SMS_SEND));
      } else {
        event.clone().event(EventType.SEND_RESET_PASSWORD)
            .detail(Details.USERNAME, username)
            .detail(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber)
            .user(user)
            .detail("status_code", String.valueOf(statusCode))
            .detail("response", responseString)
            .error(KeycloakSmsConstants.SMS_SEND_FAILED);

        Response challenge = context.form()
            .setError(KeycloakSmsConstants.MESSAGE_SMS_SEND_ERROR)
            .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
        context.failure(AuthenticationFlowError.INTERNAL_ERROR, challenge);
      }
    } catch (Exception e) {
      event.clone().event(EventType.SEND_RESET_PASSWORD)
          .detail(Details.USERNAME, username)
          .detail(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber)
          .user(user)
          .error(KeycloakSmsConstants.SMS_SEND_FAILED);

      logger.error("Failed to send sms", e);

      Response challenge = context.form()
          .setError(KeycloakSmsConstants.MESSAGE_SMS_SEND_ERROR)
          .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
      context.failure(AuthenticationFlowError.INTERNAL_ERROR, challenge);
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    context.success();
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

  }

  @Override
  public String getDisplayType() {
    return "Send Reset Sms";
  }

  @Override
  public String getReferenceCategory() {
    return null;
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
      AuthenticationExecutionModel.Requirement.REQUIRED
  };

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public String getHelpText() {
    return "Send sms to user and wait for response.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return configProperties;
  }

  private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

  static {
    ProviderConfigProperty property;
    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_URL);
    property.setLabel("Url");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The url of the sms provider");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_API_KEY);
    property.setLabel("Api Key");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The api key to the sms provider");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_API_SECRET);
    property.setLabel("Api Secret");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The api secret to the sms provider");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_FROM);
    property.setLabel("Sender");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The name of the sender. Is what is show as the sender in the sms.");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_FIELD_API_KEY);
    property.setLabel("Api Key Field");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The name of the api field for api key");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_FIELD_API_SECRET);
    property.setLabel("Api Secret Field");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The name of the api field for api secret");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_FIELD_FROM);
    property.setLabel("Sender Field");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The name of the api field for sender");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_FIELD_TEXT);
    property.setLabel("Text Field");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The name of the api field for text");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_FIELD_TO);
    property.setLabel("To Field");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The name of the api field for recipient");
    configProperties.add(property);
  }

  @Override
  public void close() {

  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return this;
  }

  @Override
  public void init(Config.Scope config) {

  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {

  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  private static String getConfigString(AuthenticatorConfigModel config, String configName) {

    String value = "";

    if (config.getConfig() != null) {
      // Get value
      value = config.getConfig().get(configName);
    }

    return value;
  }
}