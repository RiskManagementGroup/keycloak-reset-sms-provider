package dk.rmgroup.keycloak;

public class KeycloakSmsConstants {
    public static final String ATTR_MOBILE = "mobile";

    public static final String CONF_SMS_URL = "sms-reset-password.url";
    public static final String CONF_SMS_API_KEY = "sms-reset-password.api-key";
    public static final String CONF_SMS_API_SECRET = "sms-reset-password.api-secret";
    public static final String CONF_SMS_FROM = "sms-reset-password.from";

    // SMS field names
    public static final String CONF_SMS_FIELD_TO = "sms-reset-password.field.to";
    public static final String CONF_SMS_FIELD_FROM = "sms-reset-password.field.from";
    public static final String CONF_SMS_FIELD_TEXT = "sms-reset-password.field.text";
    public static final String CONF_SMS_FIELD_API_KEY = "sms-reset-password.field.api-key";
    public static final String CONF_SMS_FIELD_API_SECRET = "sms-reset-password.field.api-secret";

    // SMS error types
    public static final String INVALID_MOBILE = "invalid_mobile";
    public static final String SMS_SEND_FAILED = "sms_send_failed";

    // Messages
    public static final String MESSAGE_SMS_SEND = "smsSentMessage";
    public static final String MESSAGE_SMS_SEND_ERROR = "smsSentErrorMessage";
}