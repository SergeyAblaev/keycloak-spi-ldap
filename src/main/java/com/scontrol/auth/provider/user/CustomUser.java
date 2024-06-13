package com.scontrol.auth.provider.user;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.LegacyUserCredentialManager;
//import org.keycloak.credential.UserCredentialManager;
import org.keycloak.models.*;
import org.keycloak.storage.adapter.AbstractUserAdapter;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class CustomUser extends AbstractUserAdapter {
    
    private final String username;
    private final String email;
    private final String firstName;
    private final String lastName;
    private final String birthDate;
    private final Set<RoleModel> roles = new HashSet<>();

    private CustomUser(KeycloakSession session, RealmModel realm,
      ComponentModel storageProviderModel,
      String username,
      String email,
      String firstName,
      String lastName,
      String birthDate ) {
        super(session, realm, storageProviderModel);
        this.username = username;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.birthDate = birthDate;
        
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getFirstName() {
        return firstName;
    }

    @Override
    public String getLastName() {
        return lastName;
    }

    @Override
    public String getEmail() {
        return email;
    }

    public String getBirthDate() {
        return birthDate;
    }
    
    @Override
    public Map<String, List<String>> getAttributes() {
        MultivaluedHashMap<String, String> attributes = new MultivaluedHashMap<>();
        attributes.add(UserModel.USERNAME, getUsername());
        attributes.add(UserModel.EMAIL,getEmail());
        attributes.add(UserModel.FIRST_NAME,getFirstName());
        attributes.add(UserModel.LAST_NAME,getLastName());
        attributes.add("birthDate", getBirthDate());
        return attributes;
    }

    @Override
    public void grantRole(RoleModel role) {
        System.out.println("[cimp] Granting role " + role.getName());
        roles.add(role);
    }

    protected Set<RoleModel> getRoleMappingsInternal() {
        return this.roles;
    }

    @Override
    public Set<RoleModel> getRoleMappings() {
        Set<RoleModel> set = new HashSet<>();
        if (appendDefaultRolesToRoleMappings()) set.addAll(realm.getDefaultRole().getCompositesStream().collect(Collectors.toSet()));
        set.addAll(getRoleMappingsInternal());
        return set;
    }

    @Override
    public Stream<RoleModel> getRoleMappingsStream() {
        return getRoleMappings().stream();
    }

    static class Builder {
        private final KeycloakSession session;
        private final RealmModel realm;
        private final ComponentModel storageProviderModel;
        private String username;
        private String email;
        private String firstName;
        private String lastName;
        private String birthDate;
        
        Builder(KeycloakSession session, RealmModel realm, ComponentModel storageProviderModel,String username) {
            this.session = session;
            this.realm = realm;
            this.storageProviderModel = storageProviderModel;
            this.username = username;
        }
        
        Builder email(String email) {
            this.email = email;
            return this;
        }
        
        Builder firstName(String firstName) {
            this.firstName = firstName;
            return this;
        }
        
        Builder lastName(String lastName) {
            this.lastName = lastName;
            return this;
        }
        
        Builder birthDate(String birthDate) {
            this.birthDate = birthDate;
            return this;
        }
        
        CustomUser build() {
            return new CustomUser(
              session,
              realm,
              storageProviderModel,
              username,
              email,
              firstName,
              lastName,
              birthDate);
            
        }
    }

    @Override
    public SubjectCredentialManager credentialManager() {
        return new LegacyUserCredentialManager(session, realm, this); // deprecate in vers 24.0.3
//        return new UserCredentialManager(session, realm, this);
    }
}