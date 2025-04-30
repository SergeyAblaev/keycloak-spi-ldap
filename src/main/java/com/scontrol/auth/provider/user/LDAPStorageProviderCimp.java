/**
 * 
 */
package com.scontrol.auth.provider.user;

import com.scontrol.auth.provider.ldap.store.LDAPIdentityStoreCimp;
import com.scontrol.auth.provider.ldap.store.LdapConnectionUtils;
import com.scontrol.auth.provider.mapper.CimpStorageMapperManager;
import com.scontrol.auth.provider.mapper.LDAPStorageMapperCimp;
import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;
import org.keycloak.common.constants.KerberosConstants;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.*;
//import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.federation.kerberos.KerberosPrincipal;
import org.keycloak.models.*;
import org.keycloak.models.cache.CachedUserModel;
import org.keycloak.models.cache.UserCache;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.utils.ReadOnlyUserModelDelegate;
import org.keycloak.storage.*;
import org.keycloak.storage.adapter.InMemoryUserAdapter;
import org.keycloak.storage.adapter.UpdateOnlyChangeUserModelDelegate;
import org.keycloak.storage.ldap.*;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.Condition;
import org.keycloak.storage.ldap.idm.query.EscapeStrategy;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQueryConditionsBuilder;
import org.keycloak.storage.ldap.kerberos.LDAPProviderKerberosConfig;
import org.keycloak.storage.ldap.mappers.*;
import org.keycloak.storage.user.ImportedUserValidation;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;
import java.util.stream.Stream;

import static com.scontrol.auth.provider.user.CimpUserStorageProviderConstants.*;
import static com.scontrol.auth.provider.user.CimpUserStorageProviderFactory.domainsMap;

public class LDAPStorageProviderCimp implements UserStorageProvider,
        UserLookupProvider,
        CredentialInputValidator,
        UserQueryProvider,
        ImportedUserValidation {
    public static final String SEARCH_BASE_POSTFIX = ",DC=com";
    public static final String LMOPERATOR_BO = "LMOperatorBO";
    public static final String LMVIEWER_BO = "LMViewerBO";
    public static final String LMOPERATOR_MKTG = "LMOperatorMktg";
    public static final String LMVIEWER_MKTG = "LMViewerMktg";
    public static final String SEARCH_BASE_PREFIX = "DC=";
    public static final String SLASH = "\\";
    public static final String BACK_SLASH = "/";
    public static final String COLON = ":";
    public static final String CIMP_TAG = "[cimp] ";
    private static final Logger logger = Logger.getLogger(LDAPStorageProviderCimp.class);
    public static final String EMPTY_STRING = "";
    private KeycloakSession ksession;
    //    private ComponentModel model;   //Todo Origin LDAP is:  UserStorageProviderModel model;
    private CimpUserStorageProviderModel model;
    protected LDAPIdentityStoreCimp ldapIdentityStore;
    private CimpUserStorageProviderFactory factory;
    protected EditMode editMode;
    protected LDAPProviderKerberosConfig kerberosConfig;
    protected PasswordUpdateCallback updater;
    protected CimpStorageMapperManager mapperManager;
    protected CimpStorageUserManager userManager;
    private LDAPMappersComparator ldapMappersComparator;
    private final static ConcurrentHashMap<String, String> cashedCredentials = new ConcurrentHashMap<>();
    private final static ConcurrentHashMap<String, UserModel> cashedUserModels = new ConcurrentHashMap<>();
    private final String domainName;
    protected final Set<String> supportedCredentialTypes = new HashSet<>();
    private static final int DEFAULT_MAX_RESULTS = Integer.MAX_VALUE >> 1;

    public LDAPStorageProviderCimp(CimpUserStorageProviderFactory factory, KeycloakSession session, ComponentModel model, LDAPIdentityStoreCimp ldapIdentityStore, String domainName) {
        logger.infof("[CustomUserStorageProvider] class loaded!");
        this.factory = factory;
        this.ksession = session;
        this.model = new CimpUserStorageProviderModel(model);
        this.ldapIdentityStore = ldapIdentityStore;
        this.editMode = ldapIdentityStore.getConfig().getEditMode();
        this.mapperManager = new CimpStorageMapperManager(this);
        this.userManager = new CimpStorageUserManager(this);
        supportedCredentialTypes.add(PasswordCredentialModel.TYPE);
        this.domainName=domainName;
//        this.kerberosConfig = new LDAPProviderKerberosConfig(model);
//        if (kerberosConfig.isAllowKerberosAuthentication()) {
//            supportedCredentialTypes.add(UserCredentialModel.KERBEROS);
//        }

        ldapMappersComparator = new LDAPMappersComparator(getLdapIdentityStore().getConfig());
    }


//    protected PasswordHashProvider getHashProvider(PasswordPolicy policy) {
//        PasswordHashProvider hash = (PasswordHashProvider)this.ksession.getProvider(PasswordHashProvider.class, policy.getHashAlgorithm());
//        if (hash == null) {
//            logger.warnv("Realm PasswordPolicy PasswordHashProvider {0} not found", policy.getHashAlgorithm());
//            return (PasswordHashProvider)this.ksession.getProvider(PasswordHashProvider.class, "pbkdf2-sha256");
//        } else {
//            return hash;
//        }
//    }

//    public PasswordCredentialModel getPasswordFromSession(RealmModel realm, UserModel user) {
//        List<CredentialModel> passwords = (List)user.credentialManager().getStoredCredentialsByTypeStream(this.getType()).collect(Collectors.toList());
//        return passwords.isEmpty() ? null : PasswordCredentialModel.createFromCredentialModel((CredentialModel)passwords.get(0));
//    }

//    //как его хранить в таком формате, или просто в мапе строкой сохранить,?
//    public void storePassword(UserModel user, CredentialModel password) {
//        PasswordCredentialModel newPassword = hash.encodedCredential(input.getChallengeResponse(), policy.getHashIterations());
//        newPassword.setId(password.getId());
//        newPassword.setCreatedDate(password.getCreatedDate());
//        newPassword.setUserLabel(password.getUserLabel());
//        user.credentialManager().updateStoredCredential(newPassword);
//    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {  //Todo here we extend CredentialInputValidator
        logger.info(CIMP_TAG + "isValid logon check for User: "+ user.getUsername());
//  Wrong code!      String selectedDomain = user.getFirstAttribute("selected_domain"); // or from session //righ vers: getValue(decodedFormParameters, "domain");
//        logger.infof("{} FRONT Selected domain: {}", CIMP_TAG, selectedDomain);
//        if (selectedDomain == null) {
//            logger.infof("{} FRONT Selected domain is null", CIMP_TAG);
//        } else {
//            String ldapHost = domainMap.get(selectedDomain.toUpperCase()); //here we get user selected ldapHost !
//            logger.infof("{} FRONT user selected ldapHost: {}", CIMP_TAG, ldapHost);
//        }

        if (!(input instanceof UserCredentialModel)) return false;
        boolean configuredLocally = ((LegacyUserCredentialManager) user.credentialManager()).isConfiguredLocally(PasswordCredentialModel.TYPE);
        if (input.getType().equals(PasswordCredentialModel.TYPE) && !configuredLocally) {
            if (cashedCredentials.get(user.getUsername()).equals(input.getChallengeResponse())) {
                return true;
            }
//            return validPassword(realm, user, input.getChallengeResponse());
        } else {
            return false; // invalid cred type
        }
        return false;
    }

    public String getType() {
        return "password";
    }

    public void setUpdater(PasswordUpdateCallback updater) {
        this.updater = updater;
    }

    public KeycloakSession getSession() {
        return ksession;
    }

    public LDAPIdentityStoreCimp getLdapIdentityStore() {
        return this.ldapIdentityStore;
    }

    public EditMode getEditMode() {
        return editMode;
    }

    public CimpUserStorageProviderModel getModel() {
        return model;
    }

//    public LDAPProviderKerberosConfig getKerberosConfig() {
//        return kerberosConfig;
//    }

    public CimpStorageMapperManager getMapperManager() {
        return mapperManager;
    }

    public CimpStorageUserManager getUserManager() {
        logger.info("[Cimp] getUserManager");
        return userManager;
    }


    @Override
    public void close() {
//        cashedCredentials.clear();  - cashed user not repeatable login in LDAP
        logger.infof("[Cimp] close() - here NO need to clean stored password!");
    }


    @Override
    public UserModel getUserById(RealmModel realm, String id) { //id=f:c71d2c9f-e512-48e6-87d1-94ddb94f3d65:cimpdomain1/user3   realm=58141f7b-32fb-4069-a165-c3f33f30560d@618f355d
        logger.infof(CIMP_TAG + "getUserById {}",id);
        StorageId sid = new StorageId(id);
        String externalId = sid.getExternalId();
        if (cashedUserModels.containsKey(externalId)) {
            UserModel userModel = cashedUserModels.get(externalId);
            if (userModel.getId().equals(id)) {
                String sessionStr = ((CustomUser) userModel).getSessionStr();
                logger.infof("cashedUserModels.get ksession: "+ ksession.toString() +" vs "+ sessionStr);
                //Inside of userModel have KeycloakSession! If diff - trow except from infinispan cashe "Cannot access delegate without a transaction"!
                //FixMe - for awoid TWICE query to LDAP, TRY create builder for new userModel object for copy all field except session!!
                if (ksession.toString().equals(sessionStr)) {
                    return userModel;
                }
            }
        }
        //if we don't get from cash - get a new query to LDAP
        logger.infof(CIMP_TAG + "get a new query to LDAP for Id: {}",id);
        return getUserByUsername(realm, externalId);
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) { //here 1st calling after UI form
        logger.infof(CIMP_TAG + "getUserByUsername({})",username); // cimpdomain1/user3
        return  getUserFromDomain(realm, username);
    }
    //Todo - try write here our JS logic connect to MS-AD!
    private CustomUser getUserFromDomain(RealmModel realm, String username) {
        //Hi priority for selected domain name, oppposite the writed into username!
        MultivaluedMap<String, String> decodedFormParameters = ksession.getContext().getHttpRequest().getDecodedFormParameters();
        String domain = getValue(decodedFormParameters, "domain");
        logger.infof("{} FORM domain: {}", CIMP_TAG, domain);

        String username_without_domain;

        if (domain == null || domain.equals("null")) {
            //try to check domain in username
            int indexOf = username.indexOf(SLASH);
            if (indexOf == -1) {
                indexOf = username.indexOf(BACK_SLASH);
                if (indexOf == -1) {
                    indexOf = username.indexOf(COLON);
                    if (indexOf == -1) {
                        return null;
                    }
                }
            }
            domain = username.substring(0, indexOf);
            username_without_domain = username.substring(indexOf + 1);
        } else {
            //try to add domain into username
            username_without_domain = username;
            username = domain.concat(":" + username_without_domain);
        }


        String password = getValue(decodedFormParameters, PasswordCredentialModel.TYPE);
        if (password == null ) { //try to check cashed credentials
            password = cashedCredentials.get(username);
        }

        Attributes attributes;
        try {

            Map<String, String> domainMap = domainsMap.get(domain.toUpperCase());
            if (domainMap == null) {
                return null;
            }
            String domainName = domainMap.get(CONFIG_KEY_DOMAINNAME);
            String domainIP = domainMap.get(CONFIG_KEY_IP_ADDRESS);
            String port = domainMap.get(CONFIG_KEY_PORT);
            String searchBase = String.format(domainMap.get(LDAPConstants.BASE_DN), domainName);
            String searchFilter = String.format(domainMap.get(LDAPConstants.CUSTOM_USER_SEARCH_FILTER), username_without_domain);

            attributes = LdapConnectionUtils.connect2LdapSearchUser(username_without_domain, password, domainIP, searchBase, port, searchFilter);
            if (attributes == null) {
                logger.errorf(" %s Directory server return an EMPTY attributes for user %s! Check 'User LDAP filter' is correct? ", CIMP_TAG, username_without_domain);
                return null;
            }
        } catch (NamingException e) {
            logger.errorf(" %s ldapConnection ERROR for user %s : %s ", CIMP_TAG, username_without_domain, e.getMessage());
            return null;
        }
        logger.info("found user, attributes: "+ attributes);

        Map<String, String> rs = new HashMap<>(); //Todo - remove Map
        rs.put("username", username);
        Attribute mailAttribute = attributes.get("mail");
        String mail= EMPTY_STRING;
        if (mailAttribute != null) {
            mail = mailAttribute.toString();
            int count = mail.indexOf(": ")+2;
            if (mail.length()>count) {
                mail = mail.substring(count+2);
            }
        }
        rs.put("email", mail);
        rs.put("firstName", EMPTY_STRING); //Fixme - wtf here is EMPTY_STRING?
        rs.put("lastName", EMPTY_STRING);   //Fixme - add parsing for this!
        rs.put("birthDate", EMPTY_STRING);

        cashedCredentials.put(username, password);

//Todo convert code for domain query!
        CustomUser user = new CustomUser.Builder(ksession, realm, model, rs.get("username"))

                .email(rs.get("email"))
                .firstName(rs.get("firstName"))
                .lastName(rs.get("lastName"))
                .birthDate(rs.get("birthDate"))
                .build();

        try {
            Attribute memberofAttr = attributes.get("memberof");
            if (memberofAttr != null) {
                logger.infof(CIMP_TAG + "found memberof, attributes: " + memberofAttr); //for DOMAIN2 not found ANY!: memberof=memberOf: CN=LMOperatorBO,CN=Users,DC=cimpdomain1,DC=com, CN=Allowed RODC Password Replication Group,CN=Users,DC=cimpdomain1,DC=com
                NamingEnumeration<?> memberof = memberofAttr.getAll();
                while (memberof.hasMore()) {
                    String memberStr = memberof.next().toString();

                    //Roles must be setted in Realm.JSON
                    logger.infof(CIMP_TAG + "have member of: " + memberStr);
                    if (memberStr.contains(LMOPERATOR_BO)) {
                        user.grantRole(realm.getRole(LMOPERATOR_BO));
                    }
                    if (memberStr.contains(LMVIEWER_BO)) {
                        user.grantRole(realm.getRole(LMVIEWER_BO));
                    }
                    if (memberStr.contains(LMVIEWER_MKTG)) {
                        user.grantRole(realm.getRole(LMVIEWER_MKTG));
                    }
                    if (memberStr.contains(LMOPERATOR_MKTG)) {
                        user.grantRole(realm.getRole(LMOPERATOR_MKTG));
                    }
                }
            } else {
                logger.infof(CIMP_TAG + "not found ANY! memberof!"); //for DOMAIN2 not found ANY!: memberof=memberOf:
            }
        } catch (NamingException e) {
            logger.error(CIMP_TAG + "ldap NamingException ERROR: " + e.getMessage());
            // throw new RuntimeException(e);
        }
        logger.infof("cashedUserModels.put ksession: "+ ksession.toString());
        cashedUserModels.put(username, user);

        return user;
    }


//    private String getFormPassword(MultivaluedMap<String, String> decodedFormParameters) {
//        return getValue(decodedFormParameters, PasswordCredentialModel.TYPE);
//    }

//    private String getFormDomain(MultivaluedMap<String, String> decodedFormParameters) {
//        String key = "domain";//Here is form result!!  decodedFormParameters.get("domain"); // value = DOMAIN1
//        return getValue(decodedFormParameters, "domain");
//    }

    private static String getValue(MultivaluedMap<String, String> decodedFormParameters, String key) {
        String value = null;
        List<String> strings = decodedFormParameters.get(key);
        if (strings != null && !strings.isEmpty()){
            value = strings.get(0);
        }
        return value;
    }

    protected LDAPObject queryByEmail(RealmModel realm, String email) {
        logger.info("[Cimp] queryByEmail");
        try (LDAPQueryCimp ldapQuery = LDAPUtilsCimp.createQueryForUserSearch(this, realm)) {
            LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();

            // Mapper should replace "email" in parameter name with correct LDAP mapped attribute
            Condition emailCondition = conditionsBuilder.equal(UserModel.EMAIL, email, EscapeStrategy.DEFAULT);
            ldapQuery.addWhereCondition(emailCondition);

            return ldapQuery.getFirstResult();
        }
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        logger.infof("{} getUserByEmail({})", CIMP_TAG, email);
        //check domain
        MultivaluedMap<String, String> decodedFormParameters = ksession.getContext().getHttpRequest().getDecodedFormParameters();
        String domain = getValue(decodedFormParameters, "domain");
        if (domain == null) {
            return null;
        }
        logger.infof("{} FORM domain: {}", CIMP_TAG, domain);

        LDAPObject ldapUser = queryByEmail(realm, email);
        if (ldapUser == null) {
            return null;
        }

        // Check here if user already exists
        String ldapUsername = LDAPUtils.getUsername(ldapUser, ldapIdentityStore.getConfig());
        UserModel user = UserStoragePrivateUtil.userLocalStorage(ksession).getUserByUsername(realm, ldapUsername);

        if (user != null) {
            LDAPUtils.checkUuid(ldapUser, ldapIdentityStore.getConfig());
            // If email attribute mapper is set to "Always Read Value From LDAP" the user may be in Keycloak DB with an old email address
            if (ldapUser.getUuid().equals(user.getFirstAttribute(LDAPConstants.LDAP_ID))) {
                return proxy(realm, user, ldapUser, false);
            }
            throw new ModelDuplicateException("User with username '" + ldapUsername + "' already exists in Keycloak. It conflicts with LDAP user with email '" + email + "'");
        }

        return importUserFromLDAP(ksession, realm, ldapUser);
    }

    public Set<String> getSupportedCredentialTypes() {
        return new HashSet<>(this.supportedCredentialTypes);
    }


    @Override
    public boolean supportsCredentialType(String credentialType) {
        logger.infof("[I57] supportsCredentialType({})",credentialType);
        return getSupportedCredentialTypes().contains(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        logger.infof("[I57] isConfiguredFor(realm={},user={},credentialType={})",realm.getName(), user.getUsername(), credentialType);
        return getSupportedCredentialTypes().contains(credentialType);
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult, Integer maxResults) {
        logger.infof(CIMP_TAG + "getGroupMembersStream getUsers: realm={}", realm.getName());
        int first = firstResult == null ? 0 : firstResult;
        int max = maxResults == null ? DEFAULT_MAX_RESULTS : maxResults;
        return realm.getComponentsStream(model.getId(), LDAPStorageMapper.class.getName())
                .sorted(ldapMappersComparator.sortAsc())
                .map(mapperModel ->
                        mapperManager.getMapper(mapperModel).getGroupMembers(realm, group, first, max))
                .filter(((Predicate<List>) List::isEmpty).negate())
                .map(List::stream)
                .findFirst().orElse(Stream.empty());
    }

    @Override
    public Stream<UserModel> getRoleMembersStream(RealmModel realm, RoleModel role, Integer firstResult, Integer maxResults) {
        int first = firstResult == null ? 0 : firstResult;
        int max = maxResults == null ? DEFAULT_MAX_RESULTS : maxResults;

        return realm.getComponentsStream(model.getId(), LDAPStorageMapper.class.getName())
                .sorted(ldapMappersComparator.sortAsc())
                .map(mapperModel -> mapperManager.getMapper(mapperModel).getRoleMembers(realm, role, first, max))
                .filter(((Predicate<List>) List::isEmpty).negate())
                .map(List::stream)
                .findFirst().orElse(Stream.empty());
    }


    /**
     * It supports
     * <ul>
     *     <li>{@link UserModel#FIRST_NAME}</li>
     *     <li>{@link UserModel#LAST_NAME}</li>
     *     <li>{@link UserModel#EMAIL}</li>
     *     <li>{@link UserModel#USERNAME}</li>
     * </ul>
     *
     * Other fields are not supported. The search for LDAP REST endpoints is done in the context of fields which are stored in LDAP (above).
     */
//    @Override  //ORIGINAL!
//    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult, Integer maxResults) {
//        String search = params.get(UserModel.SEARCH);
//        Stream<LDAPObject> result = search != null ?
//                searchLDAP(realm, search, firstResult, maxResults) :
//                searchLDAPByAttributes(realm, params, firstResult, maxResults);
//
//        return paginatedStream(result.filter(filterLocalUsers(realm)), firstResult, maxResults)
//                .map(ldapObject -> importUserFromLDAP(ksession, realm, ldapObject));
//    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult, Integer maxResults) {
        logger.infof(CIMP_TAG + "searchForUserStream getUsers: realm={}, keys={}", realm.getName(), cashedUserModels.keys());
        return cashedUserModels.values().stream().filter(el->el.getUsername().startsWith(domainName.toUpperCase()));
//        return getGroupMembersStream(realm, null, firstResult, maxResults);
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
        return Stream.empty();
    }


    /**
     * Searches LDAP using logical conjunction of params. It supports
     * <ul>
     *     <li>{@link UserModel#FIRST_NAME}</li>
     *     <li>{@link UserModel#LAST_NAME}</li>
     *     <li>{@link UserModel#EMAIL}</li>
     *     <li>{@link UserModel#USERNAME}</li>
     * </ul>
     *
     * For zero or any other param it returns all users.
     */
    private Stream<LDAPObject> searchLDAPByAttributes(RealmModel realm, Map<String, String> attributes, Integer firstResult, Integer maxResults) {

        try (LDAPQueryCimp ldapQuery = LDAPUtilsCimp.createQueryForUserSearch(this, realm)) {

            LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();

            // Mapper should replace parameter with correct LDAP mapped attributes
            if (attributes.containsKey(UserModel.USERNAME)) {
                ldapQuery.addWhereCondition(conditionsBuilder.equal(UserModel.USERNAME, attributes.get(UserModel.USERNAME), EscapeStrategy.DEFAULT_EXCEPT_ASTERISK));
            }
            if (attributes.containsKey(UserModel.EMAIL)) {
                ldapQuery.addWhereCondition(conditionsBuilder.equal(UserModel.EMAIL, attributes.get(UserModel.EMAIL), EscapeStrategy.DEFAULT_EXCEPT_ASTERISK));
            }
            if (attributes.containsKey(UserModel.FIRST_NAME)) {
                ldapQuery.addWhereCondition(conditionsBuilder.equal(UserModel.FIRST_NAME, attributes.get(UserModel.FIRST_NAME), EscapeStrategy.DEFAULT_EXCEPT_ASTERISK));
            }
            if (attributes.containsKey(UserModel.LAST_NAME)) {
                ldapQuery.addWhereCondition(conditionsBuilder.equal(UserModel.LAST_NAME, attributes.get(UserModel.LAST_NAME), EscapeStrategy.DEFAULT_EXCEPT_ASTERISK));
            }
            // for all other searchable fields: Ignoring is the fallback option, since it may overestimate the results but does not ignore matches.
            // for empty params: all users are returned (pagination applies)
            return paginatedSearchLDAP(ldapQuery, firstResult, maxResults);
        }
    }

    /**
     * Searches LDAP using logical disjunction of params. It supports
     * <ul>
     *     <li>{@link UserModel#FIRST_NAME}</li>
     *     <li>{@link UserModel#LAST_NAME}</li>
     *     <li>{@link UserModel#EMAIL}</li>
     *     <li>{@link UserModel#USERNAME}</li>
     * </ul>
     *
     * It uses multiple LDAP calls and results are combined together with respect to firstResult and maxResults
     *
     * This method serves for {@code search} param of {@link org.keycloak.services.resources.admin.UsersResource#getUsers}
     */
    private Stream<LDAPObject> searchLDAP(RealmModel realm, String search, Integer firstResult, Integer maxResults) {
//Todo что если тут попробовать коннект в Домены из примера:  LdapConnectionExample   ?
        try (LDAPQueryCimp ldapQuery = LDAPUtilsCimp.createQueryForUserSearch(this, realm)) {
            LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();

            for (String s : search.split("\\s+")) {
                List<Condition> conditions = new LinkedList<>();
                if (s.startsWith("\"") && s.endsWith("\"")) {
                    // exact search
                    s = s.substring(1, s.length() - 1);
                } else if (!s.endsWith("*")) {
                    // default to prefix search
                    s += "*";
                }

                conditions.add(conditionsBuilder.equal(UserModel.USERNAME, s.trim().toLowerCase(), EscapeStrategy.DEFAULT_EXCEPT_ASTERISK));
                conditions.add(conditionsBuilder.equal(UserModel.EMAIL, s.trim().toLowerCase(), EscapeStrategy.DEFAULT_EXCEPT_ASTERISK));
                conditions.add(conditionsBuilder.equal(UserModel.FIRST_NAME, s, EscapeStrategy.DEFAULT_EXCEPT_ASTERISK));
                conditions.add(conditionsBuilder.equal(UserModel.LAST_NAME, s, EscapeStrategy.DEFAULT_EXCEPT_ASTERISK));

                ldapQuery.addWhereCondition(conditionsBuilder.orCondition(conditions.toArray(Condition[]::new)));
            }

            return paginatedSearchLDAP(ldapQuery, firstResult, maxResults);
        }
    }

    public LDAPObject loadLDAPUserByUsername(RealmModel realm, String username) {
        try (LDAPQueryCimp ldapQuery = LDAPUtilsCimp.createQueryForUserSearch(this, realm)) {
            LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();

            String usernameMappedAttribute = this.ldapIdentityStore.getConfig().getUsernameLdapAttribute();
            Condition usernameCondition = conditionsBuilder.equal(usernameMappedAttribute, username, EscapeStrategy.DEFAULT);
            ldapQuery.addWhereCondition(usernameCondition);

            LDAPObject ldapUser = ldapQuery.getFirstResult();
            if (ldapUser == null) {
                return null;
            }

            return ldapUser;
        }
    }


    private Predicate<LDAPObject> filterLocalUsers(RealmModel realm) {
        return ldapObject -> UserStoragePrivateUtil.userLocalStorage(ksession).getUserByUsername(realm, LDAPUtils.getUsername(ldapObject, LDAPStorageProviderCimp.this.ldapIdentityStore.getConfig())) == null;
    }

    /**
     * This method leverages existing pagination support in {@link LDAPQuery#getResultList()}. It sets the limit for the query
     * based on {@code firstResult}, {@code maxResults} and {@link LDAPConfig#getBatchSizeForSync()}.
     *
     * <p/>
     * Internally it uses {@link Stream#iterate(java.lang.Object, java.util.function.Predicate, java.util.function.UnaryOperator)}
     * to ensure there will be obtained required number of users considering a fact that some of the returned ldap users could be
     * filtered out (as they might be already imported in local storage). The returned {@code Stream<LDAPObject>} will be filled
     * "on demand".
     */
    private Stream<LDAPObject> paginatedSearchLDAP(LDAPQueryCimp ldapQuery, Integer firstResult, Integer maxResults) {
        LDAPConfig ldapConfig = ldapQuery.getLdapProvider().getLdapIdentityStore().getConfig();

        if (ldapConfig.isPagination()) {

            final int limit;
            if (maxResults != null && maxResults >= 0) {
                if (firstResult != null && firstResult > 0) {
                    limit = Integer.min(ldapConfig.getBatchSizeForSync(), Integer.sum(firstResult, maxResults));
                } else {
                    limit = Integer.min(ldapConfig.getBatchSizeForSync(), maxResults);
                }
            } else {
                if (firstResult != null && firstResult > 0) {
                    limit = Integer.min(ldapConfig.getBatchSizeForSync(), firstResult);
                } else {
                    limit = ldapConfig.getBatchSizeForSync();
                }
            }

            return Stream.iterate(ldapQuery,
                    query -> {
                        //the very 1st page - Pagination context might not yet be present
                        if (query.getPaginationContext() == null) try {
                            query.initPagination();
                            //returning true for first iteration as the LDAP was not queried yet
                            return true;
                        } catch (NamingException e) {
                            throw new ModelException("Querying of LDAP failed " + query, e);
                        }
                        return query.getPaginationContext().hasNextPage();
                    },
                    query -> query
            ).flatMap(query -> {
                query.setLimit(limit);
                List<LDAPObject> ldapObjects = query.getResultList();
                if (ldapObjects.isEmpty()) {
                    return Stream.empty();
                }
                return ldapObjects.stream();
            });
        }

        return ldapQuery.getResultList().stream();
    }


//    //------------------- Implementation
//    private UserModel mapUser(RealmModel realm, ResultSet rs) throws SQLException {
//
//        DateFormat fmt = new SimpleDateFormat("yyyy-MM-dd");
//        CustomUser user = new CustomUser.Builder(ksession, realm, model, rs.getString("username"))
//          .email(rs.getString("email"))
//          .firstName(rs.getString("firstName"))
//          .lastName(rs.getString("lastName"))
//          .birthDate(rs.getDate("birthDate").toString())
//          .build();
//
//        return user;
//    }

    protected UserModel importUserFromLDAP(KeycloakSession session, RealmModel realm, LDAPObject ldapUser) {
        logger.infof(CIMP_TAG + "importUserFromLDAP");
         String ldapUsername = LDAPUtils.getUsername(ldapUser, ldapIdentityStore.getConfig());
            LDAPUtils.checkUuid(ldapUser, ldapIdentityStore.getConfig());

            UserModel imported;
            if (model.isImportEnabled()) {
                // Search if there is already an existing user, which means the username might have changed in LDAP without Keycloak knowing about it
                UserModel existingLocalUser = UserStoragePrivateUtil.userLocalStorage(session)
                        .searchForUserByUserAttributeStream(realm, LDAPConstants.LDAP_ID, ldapUser.getUuid()).findFirst().orElse(null);
                if(existingLocalUser != null){
                    imported = existingLocalUser;
                    // Need to evict the existing user from cache
                    if (UserStorageUtil.userCache(session) != null) {
                        UserStorageUtil.userCache(session).evict(realm, existingLocalUser);
                    }
                } else {
                    imported = UserStoragePrivateUtil.userLocalStorage(session).addUser(realm, ldapUsername);
                }

            } else {
                InMemoryUserAdapter adapter = new InMemoryUserAdapter(session, realm, new StorageId(model.getId(), ldapUsername).getId());
                adapter.addDefaults();
                imported = adapter;
            }
            imported.setEnabled(true);

            UserModel finalImported = imported;
            realm.getComponentsStream(model.getId(), LDAPStorageMapperCimp.class.getName())
                    .sorted(ldapMappersComparator.sortDesc())
                    .forEachOrdered(mapperModel -> {
                        if (logger.isTraceEnabled()) {
                            logger.tracef("Using mapper %s during import user from LDAP", mapperModel);
                        }
                        LDAPStorageMapperCimp ldapMapper = mapperManager.getMapper(mapperModel);
                        ldapMapper.onImportUserFromLDAP(ldapUser, finalImported, realm, true);
                    });

            String userDN = ldapUser.getDn().toString();
            if (model.isImportEnabled()) imported.setFederationLink(model.getId());
            imported.setSingleAttribute(LDAPConstants.LDAP_ID, ldapUser.getUuid());
            imported.setSingleAttribute(LDAPConstants.LDAP_ENTRY_DN, userDN);
            if(getLdapIdentityStore().getConfig().isTrustEmail()){
                imported.setEmailVerified(true);
            }
            if (kerberosConfig.isAllowKerberosAuthentication() && kerberosConfig.getKerberosPrincipalAttribute() != null) {
                String kerberosPrincipal = ldapUser.getAttributeAsString(kerberosConfig.getKerberosPrincipalAttribute());
                if (kerberosPrincipal == null) {
                    logger.warnf("Kerberos principal attribute not found on LDAP user [%s]. Configured kerberos principal attribute name is [%s]", ldapUser.getDn(), kerberosConfig.getKerberosPrincipalAttribute());
                } else {
                    KerberosPrincipal kerberosPrinc = new KerberosPrincipal(kerberosPrincipal);
                    imported.setSingleAttribute(KerberosConstants.KERBEROS_PRINCIPAL, kerberosPrinc.toString());
                }
            }
            logger.debugf("Imported new user from LDAP to Keycloak DB. Username: [%s], Email: [%s], LDAP_ID: [%s], LDAP Entry DN: [%s]", imported.getUsername(), imported.getEmail(),
                    ldapUser.getUuid(), userDN);
            UserModel proxy = proxy(realm, imported, ldapUser, false);
            return proxy;
        }


    @Override
    public UserModel validate(RealmModel realm, UserModel local) {
        logger.infof("{} validate function", CIMP_TAG);
        LDAPObject ldapObject = loadAndValidateUser(realm, local);
        if (ldapObject == null) {
            return null;
        }

        return proxy(realm, local, ldapObject, false);
    }

    protected UserModel proxy(RealmModel realm, UserModel local, LDAPObject ldapObject, boolean newUser) {
        UserModel existing = userManager.getManagedProxiedUser(local.getId());
        if (existing != null) {
            return existing;
        }

        // We need to avoid having CachedUserModel as cache is upper-layer then LDAP. Hence having CachedUserModel here may cause StackOverflowError
        if (local instanceof CachedUserModel) {
            LegacyStoreManagers datastoreProvider = (LegacyStoreManagers) ksession.getProvider(DatastoreProvider.class);
            local = datastoreProvider.userStorageManager().getUserById(realm, local.getId());

            existing = userManager.getManagedProxiedUser(local.getId());
            if (existing != null) {
                return existing;
            }
        }

        UserModel proxied = local;

        checkDNChanged(realm, local, ldapObject); //Todo - thats wis is work? Is this for write into domain?!

//        switch (editMode) {
//            case READ_ONLY:
                if (model.isImportEnabled()) {
                    proxied = new ReadonlyLDAPUserModelDelegate(local);
                } else {
                    proxied = new ReadOnlyUserModelDelegate(local);
                }
//                break;
//            case WRITABLE:
//            case UNSYNCED:
//                // Any attempt to write data, which are not supported by the LDAP schema, should fail
//                // This check is skipped when register new user as there are many "generic" attributes always written (EG. enabled, emailVerified) and those are usually unsupported by LDAP schema
//                if (!model.isImportEnabled() && !newUser) {
//                    UserModel readOnlyDelegate = new ReadOnlyUserModelDelegate(local, ModelException::new);
//                    proxied = new LDAPWritesOnlyUserModelDelegate(readOnlyDelegate, this);
//                }
//                break;
//        }

        AtomicReference<UserModel> proxy = new AtomicReference<>(proxied);
        realm.getComponentsStream(model.getId(), org.keycloak.storage.ldap.mappers.LDAPStorageMapper.class.getName())
                .sorted(ldapMappersComparator.sortAsc())
                .forEachOrdered(mapperModel -> {
                    LDAPStorageMapperCimp ldapMapper = mapperManager.getMapper(mapperModel);
                    proxy.set(ldapMapper.proxy(ldapObject, proxy.get(), realm));
                });
        proxied = proxy.get();

        if (!model.isImportEnabled()) {
            proxied = new UpdateOnlyChangeUserModelDelegate(proxied);
        }

        userManager.setManagedProxiedUser(proxied, ldapObject);

        return proxied;
    }

    private void checkDNChanged(RealmModel realm, UserModel local, LDAPObject ldapObject) {
        String dnFromDB = local.getFirstAttribute(LDAPConstants.LDAP_ENTRY_DN);
        String ldapDn = ldapObject.getDn() == null? null : ldapObject.getDn().toString();
        if (ldapDn != null && !ldapDn.equals(dnFromDB)) {
            logger.debugf("Updated LDAP DN of user '%s' to '%s'", local.getUsername(), ldapDn);
            local.setSingleAttribute(LDAPConstants.LDAP_ENTRY_DN, ldapDn);

            UserCache userCache = UserStorageUtil.userCache(ksession);
            if (userCache != null) {
                userCache.evict(realm, local);
            }
        }
    }


    /**
     * @param local
     * @return ldapUser corresponding to local user or null if user is no longer in LDAP
     */
    protected LDAPObject loadAndValidateUser(RealmModel realm, UserModel local) {
        LDAPObject existing = userManager.getManagedLDAPUser(local.getId());
        if (existing != null) {
            return existing;
        }

        String uuidLdapAttribute = local.getFirstAttribute(LDAPConstants.LDAP_ID);

        LDAPObject ldapUser = loadLDAPUserByUuid(realm, uuidLdapAttribute);

        if(ldapUser == null){
            return null;
        }
        LDAPUtils.checkUuid(ldapUser, ldapIdentityStore.getConfig());

        if (ldapUser.getUuid().equals(local.getFirstAttribute(LDAPConstants.LDAP_ID))) {
            return ldapUser;
        } else {
            logger.warnf("LDAP User invalid. ID doesn't match. ID from LDAP [%s], LDAP ID from local DB: [%s]", ldapUser.getUuid(), local.getFirstAttribute(LDAPConstants.LDAP_ID));
            return null;
        }
    }

    public LDAPObject loadLDAPUserByUuid(RealmModel realm, String uuid) {
        if(uuid == null){
            return null;
        }
        try (LDAPQueryCimp ldapQuery = LDAPUtilsCimp.createQueryForUserSearch(this, realm)) {
            LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();

            String uuidLDAPAttributeName = this.ldapIdentityStore.getConfig().getUuidLDAPAttributeName();
            Condition usernameCondition = conditionsBuilder.equal(uuidLDAPAttributeName, uuid, EscapeStrategy.DEFAULT);
            ldapQuery.addWhereCondition(usernameCondition);

            return ldapQuery.getFirstResult();
        }
    }

}
