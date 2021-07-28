package com.purplehillsbooks.ssofi;

import java.util.Hashtable;

import javax.naming.NamingEnumeration;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import com.purplehillsbooks.json.JSONException;


/**
 * Collect all the LDAP specific functionality into this class
 */
public class AuthStyleLDAP implements AuthStyle {

    private String factoryInitial;
    private String providerUrl;
    private String securityAuthentication;
    private String securityPrincipal;
    private String securityCredentials;

    private String queryBase;
    private String uidAttrName;
    private String firstNameAttrName;
    private String lastNameAttrName;
    private String mailAttrName;

    //set to true for testing to avoid actually requiring a password
    private boolean ignorePasswordMode = false;

    //if set to true, this will refuse any IDs that have and at sign in them.
    private boolean rejectAtSign = false;

    //can be used to force the user name to have a Active Directory domain
    private String addDomainName = null;

    private Hashtable<String, String> htLDAP;

    /**
     * OpenID is very "bursty" meaning that a single user tends to make multiple
     * requests right in a row. So saving the last user info will probably cut
     * the LDAP requests in half or thirds. Should probably keep a cache of 10
     * users, and should time them out at time rate.
     */
    private UserInformation lastUserLookedUp;

    public AuthStyleLDAP(SSOFI ssofi) throws Exception {

        factoryInitial = ssofi.getRequiredProperty("java.naming.factory.initial");
        providerUrl = ssofi.getRequiredProperty("java.naming.provider.url");
        securityAuthentication = ssofi.getRequiredProperty("java.naming.security.authentication");
        securityPrincipal = ssofi.getRequiredProperty("java.naming.security.principal");
        securityCredentials = ssofi.getRequiredProperty("java.naming.security.credentials");
        queryBase = ssofi.getRequiredProperty("queryBase");
        uidAttrName = ssofi.getRequiredProperty("attr.name.uid");
        firstNameAttrName = ssofi.getRequiredProperty("attr.name.firstName");
        lastNameAttrName = ssofi.getRequiredProperty("attr.name.lastName");
        mailAttrName = ssofi.getRequiredProperty("attr.name.mail");


        // ignore passwords mode allows for testing sitautions
        // where people login and out of multiple users frequently
        // passwords are accepted without testing them.
        ignorePasswordMode = "yes".equalsIgnoreCase(ssofi.getSystemProperty("ignorePassword"));
        if (ignorePasswordMode) {
            System.out.println("SSOFI:  ignore password mode -- all passwords will be accepted without testing");
        }

        htLDAP = new Hashtable<String, String>();
        htLDAP.put("java.naming.factory.initial", factoryInitial);
        htLDAP.put("java.naming.provider.url", providerUrl);
        htLDAP.put("java.naming.security.authentication", securityAuthentication);
        htLDAP.put("java.naming.security.principal", securityPrincipal);
        htLDAP.put("java.naming.security.credentials", securityCredentials);

        //several web pages suggest that this setting is needed to avoid the
        //Unprocessed Continuation Reference problem
        htLDAP.put("java.naming.referral","follow");
    }

    @Override
    public String getStyleIndicator() {
        return "ldap";
    }

    private void assertValidFormat(String uid) throws Exception {
		if (rejectAtSign && uid.contains("@")) {
			throw new JSONException("Did you put an email address in?  Something is wrong because we found an @ in your id ({0}).  Please be sure to enter your windows user login id. ", uid);
		}
    }

    @Override
    public boolean authenticateUser(String userNetId, String userPwd) throws Exception {
        try {
            if (ignorePasswordMode) {
                //don't even bother checking the directory at all
                //this is for testing where you can use any password
                return true;
            }

        	assertValidFormat(userNetId);

            //because we are looking at active directory,
            //check if there is a domain name and add one if missing
            if (addDomainName!=null && !userNetId.contains("\\")) {
                userNetId = addDomainName + "\\" + userNetId;
            }

            UserInformation userInfo = getExistingUserOrNull(userNetId);
            if (userInfo==null) {
                System.out.println("SSOFI: Login: user record for ("+userNetId+") does not exist in LDAP server");
                return false;
            }
            if (userInfo.uniqueKey==null) {
                System.out.println("SSOFI: Login: user record for ("+userNetId+") malformed and does not have a DistinguishedName");
                return false;
            }



            Hashtable<String, String> envht = new Hashtable<String, String>();

            envht.put("java.naming.factory.initial",         factoryInitial);
            envht.put("java.naming.provider.url",            providerUrl);
            envht.put("java.naming.security.authentication", securityAuthentication);

            //several web pages suggest that this setting is needed to avoid the
            //Unprocessed Continuation Reference problem
            envht.put("java.naming.referral",                "follow");
            envht.put("java.naming.security.principal",      userInfo.uniqueKey);
            envht.put("java.naming.security.credentials",    userPwd);

            System.out.println("SSOFI: Login: trying for user ("+userInfo.userId+")");

            //apparently this throws an exception if login password not correct
            new InitialDirContext(envht);
            return true;
        }
        catch (Exception e) {
            String msg = e.toString();
            if (msg.contains("Invalid Credentials")) {
                JSONException.traceException(e, "SSOFI: error while authenticating: "+userNetId+", returning false.");
                return false;
            }
            throw new JSONException("Unable to authenticate user '{0}'", e, userNetId);
        }
    }

    @Override
    public UserInformation getExistingUserOrNull(String userNetId) throws Exception {
        // return the last cached value if it is the same id
        if (lastUserLookedUp != null && lastUserLookedUp.userId.equals(userNetId)) {
            return lastUserLookedUp;
        }

        UserInformation uret = new UserInformation();
        try {
        	assertValidFormat(userNetId);


            String filter = uidAttrName + "=" + userNetId;
            String base = queryBase;


            InitialDirContext dirctx = new InitialDirContext(htLDAP);
            SearchControls sctrl = new SearchControls();
            sctrl.setSearchScope(2);

            NamingEnumeration<SearchResult> results = dirctx.search(base, filter, sctrl);

            if (!results.hasMore()) {
                System.out.println("No results from searching for: "+filter+" within "+base);
                return null;
            }

            SearchResult searchResult = results.next();
            if (searchResult.getNameInNamespace() != null) {
                uret.uniqueKey = searchResult.getNameInNamespace();
            }

            Attributes attrs = searchResult.getAttributes();

            uret.userId =         checkAndGetAttr(attrs, uidAttrName, userNetId);
            String firstName = checkAndGetAttr(attrs, firstNameAttrName, userNetId);
            String lastName =  checkAndGetAttr(attrs, lastNameAttrName, userNetId);
            uret.fullName = firstName + " " + lastName;
            uret.emailAddress = checkAndGetAttr(attrs, mailAttrName, userNetId);

            System.out.println("SSOFI: uid: "+userNetId+", full name: "+uret.fullName+", emailAddress: "+uret.emailAddress+", dn: "+uret.uniqueKey);

            //must compare case insensitive because user ids are case insensitive
            //and directory will return in a different way, sometimes upper sometimes lower
            if (!userNetId.equalsIgnoreCase(uret.userId)) {
                throw new JSONException("Ooops, don't understand we were looking up user ({0}) but got user ({1})",
                        userNetId, uret.userId);
            }
            uret.alreadyInFile = true;
            lastUserLookedUp = uret;
            System.out.println("SSOFI: RETURNING USER: "+uret.getJSON().toString(2));
            return uret;
        }
        catch (Exception e) {
            if (ignorePasswordMode) {
                //to get around LDAP problems within a multinational Japanese company, when we get an exception
                //just continue and allow a user with that id and use the same for name.
                uret.userId = userNetId;
                uret.fullName = userNetId;
                return uret;
            }
            throw new JSONException("Unable to find user '{0}'", e, userNetId);
        }
    }



    @Override
    public UserInformation getOrCreateUser(String userNetId) throws Exception {
        UserInformation userInfo = getExistingUserOrNull(userNetId);
        if (userInfo!=null) {
            return userInfo;
        }
        return new UserInformation();
    }

    /**
     * Look up and get the value of an attribute.
     * If no attribute, then make a report into the log listing all the available attributes
     * since every LDAP server might be set up differently.
     */
    private String checkAndGetAttr(Attributes attrs, String key, String userId) throws Exception {

        if (attrs.get(key) != null) {
            String value = (String) attrs.get(key).get();
            System.out.println("SSOFI: found value ("+key+"="+value+") for "+userId);
            return value;
        }

        System.out.println("SSOFI: LDAP directory did not return attribute for ("+key+") for user "+userId);

        //generate a message to the log of the available attributes to use on this LDAP server
        StringBuilder sb = new StringBuilder();
        NamingEnumeration<String> allIds = attrs.getIDs();
        while (allIds.hasMore()) {
            String possibleKey = allIds.next();
            sb.append(possibleKey);
            sb.append(", ");
        }

        System.out.println("SSOFI: Here is a listing of the LDAP directory available attributes: "+sb.toString());
        return "(Unknown "+key+")";
    }

    @Override
    public void setPassword(String userId, String newPwd) throws Exception {

        DirContext ctx = new InitialDirContext(htLDAP);
        ModificationItem[] mods = new ModificationItem[1];
        mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(
                "userpassword", newPwd));
        UserInformation userInfo = getOrCreateUser(userId);
        ctx.modifyAttributes(userInfo.uniqueKey, mods);
        ctx.close();
    }

    @Override
    public void changePassword(String userId, String oldPwd, String newPwd) throws Exception {
        setPassword(userId, newPwd);

    }

    @Override
    public void changeFullName(String userId, String newName) throws Exception {
        //can't change name
        throw new Exception("LDAP version can not change the full name");
    }


    @Override
    public void updateUserInfo(UserInformation user, String password) throws Exception {
        throw new Exception("This is an LDAP based provider, and you can not update the LDAP server using this mechanism.  LDAP is read only");
    }

}
