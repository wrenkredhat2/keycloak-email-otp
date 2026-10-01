package com.example.keycloak.authenticator;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.email.EmailException;

import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class EmailOtpAuthenticator implements Authenticator {

    private static final String AUTH_NOTE_KEY = "email_otp_code";
    private static final String AUTH_TTL_KEY = "email_otp_ttl";
    private static final SecureRandom RANDOM = new SecureRandom();

    static {
        System.out.println("EmailOtpAuthenticator loaded");
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        
        // Sicherstellen, dass der User existiert und eine E-Mail hat
        if (user == null || user.getEmail() == null || user.getEmail().isBlank()) {
            context.failure(AuthenticationFlowError.UNKNOWN_USER);
            return;
        }

        // 6-stelligen Code generieren
        String code = String.format("%06d", RANDOM.nextInt(1_000_000));
        String ttl  = String.format("%d", System.currentTimeMillis() + (300 * 1000L));

        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_KEY, code);
        context.getAuthenticationSession().setAuthNote(AUTH_TTL_KEY, ttl);
        
        try {
            KeycloakSession session = context.getSession();
            RealmModel realm = context.getRealm();

            // Attribute für das FreeMarker Template vorbereiten
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("user", user);
            attributes.put("code", code);

            // Den EmailTemplateProvider aus der Session holen
            EmailTemplateProvider emailTemplateProvider = session.getProvider(EmailTemplateProvider.class);
            
            // Kontext für das Template setzen
            emailTemplateProvider.setRealm(realm);
            emailTemplateProvider.setUser(user);
            emailTemplateProvider.setAuthenticationSession(context.getAuthenticationSession());

            // Senden! 
            // Keycloak sucht automatisch nach "email-otp.ftl" in:
            // - theme-resources/templates/html/email-otp.ftl
            // - theme-resources/templates/text/email-otp.ftl (falls vorhanden)

            emailTemplateProvider.send("Your One-Time Passcode", "email-otp.ftl", attributes);

        } catch (EmailException e) {
            context.failureChallenge(
                AuthenticationFlowError.INTERNAL_ERROR,
                context.form().setError("emailSendFailed").createForm("email-otp-form.ftl")
            );
            return;
        }

        // Challenge-Formular (Eingabemaske für den Code) anzeigen
        Response challenge = context.form().createForm("email-otp-form.ftl");
        context.challenge(challenge);
    }

@Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String submittedCode = formData.getFirst("otp");

        String expectedCode = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_KEY);
        String expectedttls = context.getAuthenticationSession().getAuthNote(AUTH_TTL_KEY);

        // Sicherheits-Check: Falls die Auth-Notes fehlen (z.B. Session abgelaufen)
        if (expectedCode == null || expectedttls == null) {
            Response challenge = context.form()
                .setError("sessionExpired")
                .createForm("email-otp-form.ftl");
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
            return;
        }

        long expectedttl = Long.parseLong(expectedttls);

        // Fall 1: Code ist falsch oder leer
        if (submittedCode == null || !submittedCode.equals(expectedCode)) {
            Response challenge = context.form()
                .setError("emailOtpInvalid")
                .createForm("email-otp-form.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return;
        }

        // Fall 2: Code ist RICHTIG, aber die Zeit ist abgelaufen (TTL Timeout)
        if (System.currentTimeMillis() > expectedttl) {
            // Internen State aufräumen
            context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_KEY);
            context.getAuthenticationSession().removeAuthNote(AUTH_TTL_KEY);

            Response challenge = context.form()
                .setError("emailOtpExpired")
                .createForm("email-otp-form.ftl");
            
            // Spezifischer Error-Typ für abgelaufene Codes
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challenge);
            return;
        }

        // Fall 3: Erfolg - Code richtig und innerhalb der Zeit
        context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_KEY);
        context.getAuthenticationSession().removeAuthNote(AUTH_TTL_KEY);
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return user.getEmail() != null && !user.getEmail().isBlank();
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}