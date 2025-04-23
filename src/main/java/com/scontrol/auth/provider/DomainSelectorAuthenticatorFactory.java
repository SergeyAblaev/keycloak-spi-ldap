package com.scontrol.auth.provider;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

public class DomainSelectorAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "domain-selector-authenticator";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Domain Selector Authenticator";
    }

    @Override
    public String getHelpText() {
        return "Shows domain selection dropdown before login.";
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new DomainSelectorAuthenticator();
    }

    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}

    @Override public boolean isConfigurable() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] { AuthenticationExecutionModel.Requirement.REQUIRED };
    }
    @Override public boolean isUserSetupAllowed() { return false; }

    @Override public String getReferenceCategory() { return null; }

//    @Override public boolean isAuthenticatorFactory() { return true; }

    // Configuration support methods
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.EMPTY_LIST;
    }
}
