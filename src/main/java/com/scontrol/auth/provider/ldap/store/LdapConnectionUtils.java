package com.scontrol.auth.provider.ldap.store;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.Hashtable;

public class LdapConnectionUtils {
    public static Hashtable<String, String> ENV = new Hashtable<>();

    public static Attributes connect2LdapSearchUser(String userName, String password, String domainName, String search_base) throws NamingException {
        setEnv(userName,  password,  domainName);
        // Create initial context
        DirContext ctx = new InitialDirContext(ENV);

        SearchControls searchCtls = new SearchControls();

// Specify the search scope
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String searchFilter = "(&(cn="+userName+")(objectclass=person)(objectclass=organizationalPerson)(objectclass=user))";
        NamingEnumeration<?> namingEnum = ctx.search(search_base,searchFilter, searchCtls);
        Attributes attributes = null;
        if (namingEnum.hasMore()) {
            SearchResult result = (SearchResult) namingEnum.next();
            // GET STUFF
            attributes = result.getAttributes();
        }
        namingEnum.close();
// Close the context when we're done
        ctx.close();
        return attributes;
    }

    private static void setEnv(String userName, String password, String domainName) {
        ENV.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        ENV.put(Context.SECURITY_AUTHENTICATION, "simple");
//        env.put(Context.SECURITY_PRINCIPAL, userName + "@" + domainName);
//  CIMPDOMAIN1\Administrator
//        env.put(Context.SECURITY_PRINCIPAL, "CN=user1 d1,CN=Users,DC=cimpdomain1,DC=com");  // Connected to LDAP successfully.!
        ENV.put(Context.PROVIDER_URL, "ldap://" + domainName+ ":389");
        ENV.put(Context.SECURITY_PRINCIPAL, "CN="+userName+",CN=Users,DC=cimpdomain1,DC=com");  // Connected to LDAP successfully.!
        ENV.put(Context.SECURITY_CREDENTIALS, password);
    }

}
