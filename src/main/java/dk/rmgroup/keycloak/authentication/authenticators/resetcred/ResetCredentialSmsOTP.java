package dk.rmgroup.keycloak.authentication.authenticators.resetcred;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Properties;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.json.JSONObject;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.DefaultActionTokenKey;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import dk.rmgroup.keycloak.KeycloakSmsConstants;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

public class ResetCredentialSmsOTP implements Authenticator, AuthenticatorFactory {
  private static final Logger logger = Logger.getLogger(ResetCredentialSmsOTP.class);

  public static final String PROVIDER_ID = "reset-credential-sms-otp";

  public static SecureRandom secureRandom = new SecureRandom();

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

    // Generate a random 6 digit number
    int otp = secureRandom.nextInt(999999);

    // Pads the string with leading zeros
    String otpString = String.format("%06d", otp);

    authenticationSession.setAuthNote("otp-sms", otpString);

    KeycloakSession session = context.getSession();

    Locale locale = session.getContext().resolveLocale(user);

    try {
      Properties messages = session.theme().getTheme(Theme.Type.EMAIL).getMessages(locale);
      String smsCodeMessage = new MessageFormat(messages.getProperty("smsCodeMessage"), locale)
          .format(new String[] { otpString });

      String provider = getConfigString(context.getAuthenticatorConfig(), KeycloakSmsConstants.CONF_SMS_PROVIDER);
      switch (provider) {
        case KeycloakSmsConstants.CONF_SMS_PROVIDER_BLUEIDEA:
          sendBlueIdeaSms(context, smsCodeMessage, mobileNumber, user, username);
          break;
        case KeycloakSmsConstants.CONF_SMS_PROVIDER_VONAGE:
          sendVonageSms(context, smsCodeMessage, mobileNumber, user, username);
          break;
        default:
          event.clone().event(EventType.SEND_RESET_PASSWORD)
              .detail(Details.USERNAME, username)
              .detail(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber)
              .user(user)
              .error(KeycloakSmsConstants.SMS_SEND_FAILED);
          logger.error("Failed to send sms, unknown provider: " + provider);
          Response challenge = context.form()
              .setError(KeycloakSmsConstants.MESSAGE_SMS_SEND_ERROR)
              .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
          context.failure(AuthenticationFlowError.INTERNAL_ERROR, challenge);
          break;
      }

      Response form = context.form().createForm("code-from-sms.ftl");

      context.challenge(form);
    } catch (IOException ex) {
      event.clone().event(EventType.SEND_RESET_PASSWORD)
          .detail(Details.USERNAME, username)
          .detail(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber)
          .user(user)
          .error(KeycloakSmsConstants.SMS_SEND_FAILED);

      logger.error("Failed to send sms", ex);

      Response challenge = context.form()
          .setError(KeycloakSmsConstants.MESSAGE_SMS_SEND_ERROR)
          .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
      context.failure(AuthenticationFlowError.INTERNAL_ERROR, challenge);
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    if (!validateAnswer(context)) {
      Response challenge = context.form()
          .setError("badCode")
          .createForm("code-from-sms.ftl");
      context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
      return;
    }

    context.success();
  }

  protected boolean validateAnswer(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    String secret = formData.getFirst("sms_code");
    String authNote = context.getAuthenticationSession().getAuthNote("otp-sms");
    return authNote != null && authNote.equals(secret);
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
    return "Send Reset Sms one time password";
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

  private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

  static {
    ProviderConfigProperty property;
    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_PROVIDER);
    property.setLabel("Provider");
    property.setType(ProviderConfigProperty.LIST_TYPE);
    property.setHelpText("The sms provider to use");
    property.isRequired();
    property.setOptions(new ArrayList<String>() {
      {
        add(KeycloakSmsConstants.CONF_SMS_PROVIDER_VONAGE);
        add(KeycloakSmsConstants.CONF_SMS_PROVIDER_BLUEIDEA);
      }
    });
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_API_KEY);
    property.setLabel("Vonage Api Key");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The api key for vonage. (Only used if provider is Vonage)");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_API_SECRET);
    property.setLabel("Vonage Api Secret");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The api secret for vonage. (Only used if provider is Vonage)");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_FROM);
    property.setLabel("Sender");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The name of the sender. Is what is show as the sender in the sms.");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_BLUEIDEA_EMAIL);
    property.setLabel("Blueidea Email");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The email for blueidea. (Only used if provider is Blueidea)");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_BLUEIDEA_PASSWORD);
    property.setLabel("Blueidea password");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The password for blueidea. (Only used if provider is Blueidea)");
    configProperties.add(property);

    property = new ProviderConfigProperty();
    property.setName(KeycloakSmsConstants.CONF_SMS_BLUEIDEA_PROFILE_ID);
    property.setLabel("Blueidea profile id");
    property.setType(ProviderConfigProperty.STRING_TYPE);
    property.setHelpText("The profile id for blueidea. (Only used if provider is Blueidea)");
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

  private static void sendBlueIdeaSms(AuthenticationFlowContext context, String smsTextMessage, String mobileNumber,
      UserModel user, String username) {
    EventBuilder event = context.getEvent();

    try {
      AuthenticatorConfigModel config = context.getAuthenticatorConfig();

      AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();

      String blueIdeaToken = getBlueIdeaToken(context);

      URL url = URI.create("https://api.sms-service.dk/Message/SendSingle").toURL();

      HttpURLConnection connection = (HttpURLConnection) url.openConnection();
      connection.setRequestMethod("POST");
      connection.setRequestProperty("Content-Type", "application/json");
      connection.setRequestProperty("Accept", "application/json");
      connection.setRequestProperty("Authorization", "Bearer " + blueIdeaToken);
      connection.setDoOutput(true);
      try (OutputStream os = connection.getOutputStream();
          OutputStreamWriter osw = new OutputStreamWriter(os, "UTF-8")) {

        String inputText = "{\"messageText\":\"" + smsTextMessage.replace("\n", "\\n") + "\", \"phone\":\""
            + mobileNumber + "\", \"sender\":\"" + getConfigString(config, KeycloakSmsConstants.CONF_SMS_FROM)
            + "\", \"profileId\":\"" + getConfigString(config, KeycloakSmsConstants.CONF_SMS_BLUEIDEA_PROFILE_ID)
            + "\", \"sendInstantly\":true}";

        osw.write(inputText);
        osw.flush();
      }
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

    } catch (Exception ex) {
      event.clone().event(EventType.SEND_RESET_PASSWORD)
          .detail(Details.USERNAME, username)
          .detail(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber)
          .user(user)
          .error(KeycloakSmsConstants.SMS_SEND_FAILED);

      logger.error("Failed to send sms", ex);

      Response challenge = context.form()
          .setError(KeycloakSmsConstants.MESSAGE_SMS_SEND_ERROR)
          .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
      context.failure(AuthenticationFlowError.INTERNAL_ERROR, challenge);
    }
  }

  private static String getBlueIdeaToken(AuthenticationFlowContext context) throws Exception {
    try {
      AuthenticatorConfigModel config = context.getAuthenticatorConfig();

      URL url = URI.create("https://api.sms-service.dk/User/Login").toURL();

      HttpURLConnection connection = (HttpURLConnection) url.openConnection();
      connection.setRequestMethod("POST");
      connection.setRequestProperty("Content-Type", "application/json");
      connection.setRequestProperty("Accept", "application/json");
      connection.setDoOutput(true);
      try (OutputStream os = connection.getOutputStream();
          OutputStreamWriter osw = new OutputStreamWriter(os, "UTF-8")) {

        String inputText = "{\"email\":\"" + getConfigString(config, KeycloakSmsConstants.CONF_SMS_BLUEIDEA_EMAIL)
            + "\", \"password\":\""
            + getConfigString(config, KeycloakSmsConstants.CONF_SMS_BLUEIDEA_PASSWORD) + "\"}";

        osw.write(inputText);
        osw.flush();
      }
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
        JSONObject obj = new JSONObject(responseString);
        String accessToken = obj.getString("accessToken");
        return accessToken;
      } else {
        throw new Exception(
            "Failed to get blueIdea token, status code: " + statusCode + ", response: " + responseString);
      }

    } catch (Exception ex) {
      throw new Exception("Failed to get blueIdea token", ex);
    }
  }

  private void sendVonageSms(AuthenticationFlowContext context, String smsTextMessage, String mobileNumber,
      UserModel user, String username) {
    EventBuilder event = context.getEvent();

    try {
      AuthenticatorConfigModel config = context.getAuthenticatorConfig();

      AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();

      URL url = URI.create(getConfigString(config, KeycloakSmsConstants.CONF_SMS_URL)).toURL();

      HttpURLConnection connection = (HttpURLConnection) url.openConnection();
      connection.setRequestMethod("POST");
      connection.setRequestProperty("Content-Type", "application/json");
      connection.setRequestProperty("Accept", "application/json");
      connection.setDoOutput(true);
      try (OutputStream os = connection.getOutputStream();
          OutputStreamWriter osw = new OutputStreamWriter(os, "UTF-8")) {

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
      }
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
    } catch (IOException e) {
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
}