package com.purplehillsbooks.ssofi;

import java.io.File;
import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;

import com.purplehillsbooks.json.JSONArray;
import com.purplehillsbooks.json.JSONObject;

/**
 * Holds all the information that we need for a session
 */
public class AuthSession implements Serializable {

    private static final long serialVersionUID = 1L;

    public static String baseURL;

    //This is the key for the session, and this object is
    //stored in a file with this session Id in it.
    public String sessionId;

    // if something goes wrong, note it here for display next time
    // BUT not all exception object are serializable!!!!!
    // So put a JSONObject in here instead.
    private List<String> errMsg = new ArrayList<String>();

    // this is where the entire exchange will return to once done logging in
    // by default, return to the main page of the ID server
    String return_to;

    // this is the originally passed identity to VERIFY
    String presumedId;

    // this is the verified identity that the user is logged in as
    // null when use not logged in.
    private String authIdentity;

    // this is the verified identity that the user is logged in as
    // null when use not logged in.
    private String authName;

    // FOLLOWING TWO FIELDS FOR REGISTRATION OR RESETTING PASSWORD
    // This is the email address supplied by the user and tested
    // for registering a new email address.  We keep this here
    // so it can be included in the UI template.
    String emailTested;

    // This boolean says whether the email address have been
    // confirmed during THIS SESSION.   Confirming an email
    // address allows a user to be created on demand, and also
    // allows saving of the password without the old password.
    private boolean emailConfirmed = false;

    Properties savedParams = new Properties();

    public AuthSession(String newSession) {
        sessionId = newSession;
    }

    public void changeSessionId(String newSession) {
        sessionId = newSession;
    }

    public boolean loggedIn() {
        return authIdentity != null && authIdentity.length()>0;
    }

    public void setUserOnSession(UserInformation ui) {
        if (ui==null) {
            throw new RuntimeException("login needs a UserInformation object");
        }
        authIdentity = ui.emailAddress;
        authName = ui.fullName;

        //This is the official log saying that someone logged in to the system
        System.out.println("SSOFI LOGIN: userId="+authIdentity+", name="+authName+", at "+currentTimeString());

        //we also wipe out any record of a previously sought after id, now that
        //you are logged in we don't need to remember who we thought you might be.
        presumedId = authIdentity;
    }

    public void logout() {
        //This is the official log saying that someone logged out of the system
        System.out.println("SSOFI LOGOUT: userId="+authIdentity+", name="+authName+", at "+currentTimeString());

        authIdentity = null;
        authName = null;
        emailTested = null;
        return_to = null;
        errMsg.clear();
    }

    public String loggedUserId() {
        return authIdentity;
    }

    public String loggedUserName() {
        return authName;
    }
    public void updateFullName(String newName) {
        authName = newName;
    }

    public void assureName() {
        if (authName==null || authName.length()==0) {
            authName = "User: "+authIdentity;
        }
    }
    public UserInformation getUser() {
        if (!this.loggedIn()) {
            return null;
        }
        UserInformation user = new UserInformation();
        user.userId = authIdentity;
        user.fullName = authName;
        user.emailAddress = emailTested;
        return user;
    }


    public void saveError(Exception e) {
        ArrayList<String> newErrs = new ArrayList<String>();
        Throwable runner = e;
        while (runner!=null) {
            String msg = runner.toString();
            //strip off the class name if there is one
            int pos = msg.indexOf(":");
            if (pos>0 && (msg.startsWith("java.") || msg.startsWith("com.") || msg.startsWith("org."))) {
                msg = msg.substring(pos+2);
            }
            pos = msg.indexOf("nested exception");
            if (pos>3) {
                //some exceptions unnecessarily duplicate the cause exception,
                //since we don't need it, strip it out.
                msg = msg.substring(0, pos-3);
            }
            newErrs.add(msg);
            runner = runner.getCause();
        }
        errMsg = newErrs;
    }
    public void clearError() {
        errMsg = new ArrayList<String>();
        savedParams.clear();
    }
    public List<String> getErrorList() {
        return errMsg;
    }


    public void startRegistration(String email) {
    	emailTested = email;
        emailConfirmed = false;
    }
    public void emailConfirmed(UserInformation ui) {
        authIdentity = ui.emailAddress;
        authName     = ui.fullName;
        emailTested  = ui.emailAddress;
        emailConfirmed = true;
        System.out.println("SSOFI: Email confirmed for "+emailTested);
    }
    /**
     * Email confirmation gives you the ability to change the password, but
     * after changing the password once, the bit should be turned off to
     * avoid other password changes.   The window for changing password only
     * stays open for one setting of the passwords.
     */
    public void clearConfirmBit() {
        emailConfirmed = false;
    }

    /**
     * Email address confirmed in this THIS session
     * so special rules apply.
     */
    public boolean hasJustConfirmed() {
        return emailConfirmed;
    }

    public void saveParameterList(HttpServletRequest request) {
        Enumeration<String> penum = request.getParameterNames();
        while (penum.hasMoreElements()) {
            String name = penum.nextElement();
            String val = request.getParameter(name);
            savedParams.put(name, val);
        }
    }

    public String getSavedParameter(String name) {
        return savedParams.getProperty(name);
    }





    public JSONObject userStatusAsJSON(SSOFI ssofi) throws Exception {
        JSONArray errors = new JSONArray();
        for (String msg : getErrorList()) {
            errors.put(msg);
        }

        if (!loggedIn()) {
            JSONObject jo = new JSONObject();
            jo.put("ss",  sessionId);
            jo.put("msg", "Not Logged In");
            jo.put("errors", errors);
            jo.put("baseUrl", ssofi.baseURL);
            return jo;
        }

        UserInformation user = getUser();
        JSONObject jo = user.getJSON();
        jo.put("ss",     sessionId);
        jo.put("msg",    "Logged In");

        jo.put("presumedId", this.presumedId);
        jo.put("isLoggedIn", this.loggedIn());
        jo.put("isLDAP",   ssofi.isLDAPMode);
        jo.put("isLocal", !ssofi.isLDAPMode);
        jo.put("emailConfirmed", this.emailConfirmed);

        jo.put("go",    return_to);

        return jo;
    }


    public void writeSessionToFile(File sessionFolder) throws Exception {
        JSONArray eList = new JSONArray();
        for (String em : errMsg) {
            eList.put(em);
        }

        JSONObject persistable = new JSONObject();
        persistable.put("authIdentity", authIdentity);
        persistable.put("authName",     authName);
        persistable.put("presumedId",   presumedId);
        persistable.put("regEmail",     emailTested);
        persistable.put("errMsg",       eList);
        persistable.put("return_to",    return_to);
        persistable.put("emailConfirmed", emailConfirmed);

        File sessionFile = new File(sessionFolder, sessionId+".ss");
        persistable.writeToFile(sessionFile);
    }

    public static AuthSession readOrCreateSessionFile(File sessionFolder, String sessionId) throws Exception {
        File sessionFile = new File(sessionFolder, sessionId+".ss");
        AuthSession as = new AuthSession(sessionId);
        if (sessionFile.exists()) {
            JSONObject restored = JSONObject.readFromFile(sessionFile);
            as.authIdentity = restored.optString("authIdentity");
            as.authName = restored.optString("authName");
            as.presumedId = restored.optString("presumedId");
            as.emailTested = restored.optString("regEmail");
            as.return_to = restored.optString("return_to");
            as.errMsg    = restored.getJSONArray("errMsg").getStringList();
            as.emailConfirmed = restored.optBoolean("emailConfirmed");
            return as;
        }
        else {
            as.writeSessionToFile(sessionFolder);
            System.out.println("SSOFI: brand new session for: "+sessionId);
        }
        return as;
    }



    //TODO: move this to a common location
    static final SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd-HH.mm.ss");
    public static String currentTimeString() {
        return dateFormatter.format(new Date());
    }

}
