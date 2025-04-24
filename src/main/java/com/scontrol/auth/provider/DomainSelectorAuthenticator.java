package com.scontrol.auth.provider;

import com.scontrol.auth.provider.user.CimpUserStorageProviderFactory;
import com.scontrol.auth.provider.user.LDAPStorageProviderCimp;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class DomainSelectorAuthenticator implements Authenticator {
    @Override
    public void authenticate(AuthenticationFlowContext context) {

        // Just inject the domain list into the context
        Map<String, String> domainMap = getDomainMap();
        context.form().setAttribute("domainMap", domainMap);

//        Response challenge = context.form().createLoginUsernamePassword(); // uses login.ftl
//        context.challenge(challenge);

        // Do not render anything — just move on
        context.success();
    }

    private static Map<String, String> getDomainMap() {
        Set<String> domainSet = CimpUserStorageProviderFactory.domainsMap.keySet();
        Map<String, String> domainMap = new HashMap<>();
        for (String domain : domainSet) {
            domainMap.put(domain, domain);
        }
        return domainMap;
    }

    @Override public void action(AuthenticationFlowContext context) { context.success(); }
    @Override public boolean requiresUser() { return false; }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
//            Authenticator.super.setRequiredActions(session, realm, user);
    }

    @Override
    public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
        return Authenticator.super.getRequiredActions(session);
    }

    @Override
    public boolean areRequiredActionsEnabled(KeycloakSession session, RealmModel realm) {
        return Authenticator.super.areRequiredActionsEnabled(session, realm);
    }

    @Override
    public void close() {
//        Authenticator.super.close();
    }

//    @Override public boolean configuredFor(...) { return true; }
//    @Override public void setRequiredActions(...) {}
//    @Override public void close() {}
}

