package com.scontrol.auth.provider.user;

import com.scontrol.auth.provider.ldap.store.LDAPIdentityStoreCimp;
import com.scontrol.auth.provider.ldap.store.LDAPIdentityStoreRegistryCimp;
import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.*;
import org.keycloak.storage.ldap.*;
import org.keycloak.storage.ldap.mappers.LDAPConfigDecorator;
import org.jboss.logging.Logger;
import org.keycloak.storage.ldap.mappers.LDAPStorageMapper;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.scontrol.auth.provider.user.CimpUserStorageProviderConstants.*;

public class CimpUserStorageProviderFactory implements UserStorageProviderFactory<LDAPStorageProviderCimp>
        //UserStorageProviderFactory<LDAPStorageProvider> , ImportSynchronization
{

    private static final Logger logger = Logger.getLogger(LDAPStorageProviderFactory.class);
    protected final List<ProviderConfigProperty> configProperties;
    private LDAPIdentityStoreRegistryCimp ldapStoreRegistry;

    public CimpUserStorageProviderFactory() {
        logger.infof("[CIMP] cimp. CustomUserStorageProviderFactory created");

        // Create config metadata  dn "CN=Users, DC=cimpdomain1, DC=com"
        configProperties = ProviderConfigurationBuilder.create()
                .property().name(CONFIG_KEY_DOMAINNAME)
                .label("Domain name")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("-")
                .helpText("Example: myDomain1")
                .add()
                .property().name(CONFIG_KEY_IP_ADDRESS)
                .label("Ip address")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("192.168.1.18")
                .helpText("Example: 192.168.123.45")
                .add()
                .property().name(CONFIG_KEY_PORT)
                .label("Port").type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("389")
                .helpText("Example: 389")
                .add()
                .property().name(LDAPConstants.CONNECTION_URL).label("Connection URL")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("ldap://192.168.1.18:389")
                .add()
                .property().name(LDAPConstants.USERNAME_LDAP_ATTRIBUTE).label("Username LDAP attribute")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("cn")
                .add()
                .property().name(LDAPConstants.RDN_LDAP_ATTRIBUTE).label("RDN LDAP attribute")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("cn")
                .add()
                .property().name(LDAPConstants.UUID_LDAP_ATTRIBUTE).label("UUID LDAP attribute")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("obiectGUID")
                .add()
                .property().name(LDAPConstants.USER_OBJECT_CLASSES).label("User object classes")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("person, organizationalPerson, user")
                .add()
                .property().name(LDAPConstants.USERS_DN).label("Users DN")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("CN=Users, DC=domain1, DC=com")
                .add()
                .property().name(LDAPConstants.EDIT_MODE).label("Edit mode")
                .type(ProviderConfigProperty.STRING_TYPE).defaultValue("READ_ONLY")
                .add()
                .property().name(LDAPConstants.AUTH_TYPE).label("Bind type")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("simple")
                .add()
                .property().name(LDAPConstants.BIND_DN).label("Bind DN")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("CN=Administrator,CN=Users, DC=cimpdomain1, DC=com")
                .add()
                .property().name(LDAPConstants.BIND_CREDENTIAL).label("Bind credentials")
                .type(ProviderConfigProperty.PASSWORD).defaultValue("123")
                .secret(true)

//          .property()
//            .name(CONFIG_KEY_JDBC_DRIVER)
//            .label("JDBC Driver Class")
//            .type(ProviderConfigProperty.STRING_TYPE)
//            .defaultValue("org.h2.Driver")
//            .helpText("Fully qualified class name of the JDBC driver")
//            .add()
//          .property()
//            .name(CONFIG_KEY_JDBC_URL)
//            .label("JDBC URL")
//            .type(ProviderConfigProperty.STRING_TYPE)
//            .defaultValue("jdbc:h2:mem:customdb")
//            .helpText("JDBC URL used to connect to the user database")
//                .add()
//                .property().name(CONFIG_KEY_DB_USERNAME)
//                .label("Database User")
//                .type(ProviderConfigProperty.STRING_TYPE)
//                .helpText("Username used to connect to the database")
//                .add()
//                .property().name(CONFIG_KEY_DB_PASSWORD)
//                .label("Database Password")
//                .type(ProviderConfigProperty.STRING_TYPE)
//                .helpText("Password used to connect to the database")
//                .secret(true)
                .add()
                .property().name(CONFIG_KEY_VALIDATION_QUERY)
                .label("SQL Validation Query")
                .type(ProviderConfigProperty.STRING_TYPE)
                .helpText("SQL query used to validate a connection")
                .defaultValue("select 1")
                .add()
                .build();
    }

    //Todo used aal the time for user searsh
    @Override
    public LDAPStorageProviderCimp create(KeycloakSession session, ComponentModel model)  {
        logger.infof("[I63] cimp. creating new CustomUserStorageProvider");

        Map<ComponentModel, LDAPConfigDecorator> configDecorators = getLDAPConfigDecorators(session, model);
        LDAPIdentityStoreCimp ldapIdentityStore = this.ldapStoreRegistry.getLdapStore(session, model, configDecorators);
        return new LDAPStorageProviderCimp(this, session, model, ldapIdentityStore);
    }

    protected Map<ComponentModel, LDAPConfigDecorator> getLDAPConfigDecorators(KeycloakSession session, ComponentModel ldapModel) {
        RealmModel realm = session.realms().getRealm(ldapModel.getParentId());
        return realm.getComponentsStream(ldapModel.getId(), LDAPStorageMapper.class.getName())
                .filter(mapperModel -> session.getKeycloakSessionFactory()
                        .getProviderFactory(LDAPStorageMapper.class, mapperModel.getProviderId()) instanceof LDAPConfigDecorator)
                .collect(Collectors.toMap(Function.identity(), mapperModel ->
                        (LDAPConfigDecorator) session.getKeycloakSessionFactory()
                                .getProviderFactory(LDAPStorageMapper.class, mapperModel.getProviderId())));
    }


//    @Override
//    public LDAPStorageProvider create(KeycloakSession session, ComponentModel model) {
//        Map<ComponentModel, LDAPConfigDecorator> configDecorators = getLDAPConfigDecorators(session, model);
//
//        LDAPIdentityStore ldapIdentityStore = this.ldapStoreRegistry.getLdapStore(session, model, configDecorators);
//        return new LDAPStorageProvider(this, session, model, ldapIdentityStore);
//    }


    @Override
    public String getId() {
        logger.infof("[CIMP] cimp. getId()");
        return "cimp-user-provider";
    }


    // Configuration support methods
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config) throws ComponentValidationException {

//       try (Connection c = DbUtil.getConnection(config)) {
        logger.infof("[CIMP] Testing connection...");
//           c.createStatement().execute(config.get(CONFIG_KEY_VALIDATION_QUERY));
        //Todo here is get DOMAIN connect! тут надо просто запрос как пинг без имени можно такое?

        logger.infof("[CIMP] Connection OK !");
//       }
//       catch(Exception ex) {
//           log.warn("[CIMP] Unable to validate connection: ex={}", ex.getMessage());
//           throw new ComponentValidationException("Unable to validate database connection",ex);
//       }
    }

    @Override
    public void init(Config.Scope config) {
        this.ldapStoreRegistry = new LDAPIdentityStoreRegistryCimp();
    }

    @Override
    public void close() {
        this.ldapStoreRegistry = null;
    }

    @Override
    public void onUpdate(KeycloakSession session, RealmModel realm, ComponentModel oldModel, ComponentModel newModel) {
        logger.infof("[CIMP] onUpdate()");
    }

    @Override
    public void onCreate(KeycloakSession session, RealmModel realm, ComponentModel model) {
        logger.infof("[CIMP] onCreate()");
    }

//    //    public SynchronizationResult sync(KeycloakSessionFactory sessionFactory, String realmId, UserStorageProviderModel model) {
//    public SynchronizationResult sync(KeycloakSessionFactory sessionFactory, String realmId, CimpUserStorageProviderModel model) {
//        logger.infof("[CIMP] sync()");
////            this.syncMappers(sessionFactory, realmId, model);
//        logger.infof("Sync all users from LDAP to local store: realm: %s, federation provider: %s", realmId, model.getName());
//        LDAPQuery userQuery = this.createQuery(sessionFactory, realmId, model);
//
//        SynchronizationResult var6;
//        try {
//            SynchronizationResult syncResult = this.syncImpl(sessionFactory, userQuery, realmId, model);
//            logger.infof("Sync all users finished: %s", syncResult.getStatus());
//            var6 = syncResult;
//        } catch (Throwable var8) {
//            if (userQuery != null) {
//                try {
//                    userQuery.close();
//                } catch (Throwable var7) {
//                    var8.addSuppressed(var7);
//                }
//            }
//
//            throw var8;
//        }
//
//        if (userQuery != null) {
//            userQuery.close();
//        }
//
//        return var6;
//    }
//
//    protected SynchronizationResult syncImpl(KeycloakSessionFactory sessionFactory, LDAPQuery userQuery, String realmId, ComponentModel fedModel) {
//        SynchronizationResult syncResult = new SynchronizationResult();
//        LDAPConfig ldapConfig = new LDAPConfig(fedModel.getConfig());
//        boolean pagination = ldapConfig.isPagination();
//        if (pagination) {
//            int pageSize = ldapConfig.getBatchSizeForSync();
//            boolean nextPage = true;
//
//            while (nextPage) {
//                userQuery.setLimit(pageSize);
//                List<LDAPObject> users = userQuery.getResultList();
//                nextPage = userQuery.getPaginationContext().hasNextPage();
//                SynchronizationResult currentPageSync = this.importLdapUsers(sessionFactory, realmId, fedModel, users);
//                syncResult.add(currentPageSync);
//            }
//        } else {
//            List<LDAPObject> users = userQuery.getResultList();
//            SynchronizationResult currentSync = this.importLdapUsers(sessionFactory, realmId, fedModel, users);
//            syncResult.add(currentSync);
//        }
//
//        return syncResult;
//    }
//
//    SynchronizationResult syncSince(Date var1, KeycloakSessionFactory var2, String var3, CimpUserStorageProviderModel var4) {
//        logger.infof("[CIMP] syncSince()");
//
//    }
//
//
//
//    protected SynchronizationResult importLdapUsers(KeycloakSessionFactory sessionFactory, final String realmId, final ComponentModel fedModel, List<LDAPObject> ldapUsers) {
//        final SynchronizationResult syncResult = new SynchronizationResult();
//
//        class BooleanHolder {
//            private boolean value = true;
//
//            BooleanHolder() {
//            }
//        }
//
//        final BooleanHolder exists = new BooleanHolder();
//        Iterator var7 = ldapUsers.iterator();
//
//        while(var7.hasNext()) {
//            final LDAPObject ldapUser = (LDAPObject)var7.next();
//
//            try {
//                KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {
//                    public void run(KeycloakSession session) {
////                        LDAPStorageProvider ldapFedProvider = (LDAPStorageProvider)session.getProvider(UserStorageProvider.class, fedModel);
//                        CimpUserStorageProvider ldapFedProvider = (LDAPStorageProvider)session.getProvider(UserStorageProvider.class, fedModel);
//                        RealmModel currentRealm = session.realms().getRealm(realmId);
//                        session.getContext().setRealm(currentRealm);
//                        String username = LDAPUtils.getUsername(ldapUser, ldapFedProvider.getLdapIdentityStore().getConfig());
//                        exists.value = true;
//                        LDAPUtils.checkUuid(ldapUser, ldapFedProvider.getLdapIdentityStore().getConfig());
//                        UserModel currentUserLocal = UserStoragePrivateUtil.userLocalStorage(session).getUserByUsername(currentRealm, username);
//                        Optional<UserModel> userModelOptional = UserStoragePrivateUtil.userLocalStorage(session).searchForUserByUserAttributeStream(currentRealm, "LDAP_ID", ldapUser.getUuid()).findFirst();
//                        if (!userModelOptional.isPresent() && currentUserLocal == null) {
//                            exists.value = false;
//                            ldapFedProvider.importUserFromLDAP(session, currentRealm, ldapUser);
//                            syncResult.increaseAdded();
//                        } else {
//                            UserModel currentUser = userModelOptional.isPresent() ? (UserModel)userModelOptional.get() : currentUserLocal;
//                            if (fedModel.getId().equals(currentUser.getFederationLink()) && ldapUser.getUuid().equals(currentUser.getFirstAttribute("LDAP_ID"))) {
//                                LDAPMappersComparator ldapMappersComparator = new LDAPMappersComparator(ldapFedProvider.getLdapIdentityStore().getConfig());
//                                currentRealm.getComponentsStream(fedModel.getId(), LDAPStorageMapper.class.getName()).sorted(ldapMappersComparator.sortDesc()).forEachOrdered((mapperModel) -> {
//                                    LDAPStorageMapper ldapMapper = ldapFedProvider.getMapperManager().getMapper(mapperModel);
//                                    ldapMapper.onImportUserFromLDAP(ldapUser, currentUser, currentRealm, false);
//                                });
//                                UserCache userCache = UserStorageUtil.userCache(session);
//                                if (userCache != null) {
//                                    userCache.evict(currentRealm, currentUser);
//                                }
//
//                                CimpUserStorageProviderFactory.logger.debugf("Updated user from LDAP: %s", currentUser.getUsername());
//                                syncResult.increaseUpdated();
//                            } else {
//                                CimpUserStorageProviderFactory.logger.warnf("User with ID '%s' is not updated during sync as he already exists in Keycloak database but is not linked to federation provider '%s'", ldapUser.getUuid(), fedModel.getName());
//                                syncResult.increaseFailed();
//                            }
//                        }
//
//                    }
//                });
//            } catch (ModelException var10) {
//                ModelException me = var10;
//                logger.error("Failed during import user from LDAP", me);
//                syncResult.increaseFailed();
//                if (!exists.value) {
//                    KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {
//                        public void run(KeycloakSession session) {
//                            LDAPStorageProvider ldapFedProvider = (LDAPStorageProvider)session.getProvider(UserStorageProvider.class, fedModel);
//                            RealmModel currentRealm = session.realms().getRealm(realmId);
//                            session.getContext().setRealm(currentRealm);
//                            String username = null;
//
//                            try {
//                                username = LDAPUtils.getUsername(ldapUser, ldapFedProvider.getLdapIdentityStore().getConfig());
//                            } catch (ModelException var7) {
//                            }
//
//                            if (username != null) {
//                                UserModel existing = UserStoragePrivateUtil.userLocalStorage(session).getUserByUsername(currentRealm, username);
//                                if (existing != null) {
//                                    UserCache userCache = UserStorageUtil.userCache(session);
//                                    if (userCache != null) {
//                                        userCache.evict(currentRealm, existing);
//                                    }
//
//                                    UserStoragePrivateUtil.userLocalStorage(session).removeUser(currentRealm, existing);
//                                }
//                            }
//
//                        }
//                    });
//                }
//            }
//        }
//
//        return syncResult;
//    }


//    protected void syncMappers(KeycloakSessionFactory sessionFactory, final String realmId, final ComponentModel model) {
//        KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {
//            public void run(KeycloakSession session) {
//                RealmModel realm = session.realms().getRealm(realmId);
//                session.getContext().setRealm(realm);
//                session.getProvider(UserStorageProvider.class, model);
//                realm.getComponentsStream(model.getId(), LDAPStorageMapper.class.getName()).forEach((mapperModel) -> {
//                    SynchronizationResult syncResult = ((LDAPStorageMapper)session
//                            .getProvider(LDAPStorageMapper.class, mapperModel)).syncDataFromFederationProviderToKeycloak(realm); //LDAPStorageProviderFactory
//                    if (syncResult.getAdded() > 0 || syncResult.getUpdated() > 0 || syncResult.getRemoved() > 0 || syncResult.getFailed() > 0) {
//                        CimpUserStorageProviderFactory.logger.infof("Sync of federation mapper '%s' finished. Status: %s", mapperModel.getName(), syncResult.toString());
//                    }
//
//                });
//            }
//        });
}
