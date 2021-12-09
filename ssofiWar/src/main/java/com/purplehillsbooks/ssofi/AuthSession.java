package com.purplehillsbooks.ssofi;

import java.io.File;
import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import com.purplehillsbooks.json.JSONArray;
import com.purplehillsbooks.json.JSONException;
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

    private UserInformation authUser = null;

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
        authUser = ui;
        authIdentity = ui.userId;
        emailTested = ui.emailAddress;

        //This is the official log saying that someone logged in to the system
        System.out.println("SSOFI ("+sessionId+"): login successful, userId="+authIdentity+", name="+authUser.fullName+", at "+currentTimeString());

        //we also wipe out any record of a previously sought after id, now that
        //you are logged in we don't need to remember who we thought you might be.
        presumedId = authIdentity;
    }

    public void logout() {
        //This is the official log saying that someone logged out of the system
        System.out.println("SSOFI ("+sessionId+"): logout successful for user: "+authIdentity+", at "+currentTimeString());

        authIdentity = null;
        emailTested = null;
        return_to = null;
        errMsg.clear();
        authUser = null;
    }

    public String loggedUserId() {
        return authIdentity;
    }

    public String loggedUserName() {
        if (authUser==null) {
            return null;
        }
        return authUser.fullName;
    }
    public void updateFullName(String newName) {
        if (authUser==null) {
            throw new RuntimeException("Can not set a new name on a user when nobody is logged in");
        }
        authUser.fullName = newName;
    }

    public void assureName() {
        if (authUser.fullName==null || authUser.fullName.length()==0) {
            authUser.fullName = "User: "+authIdentity;
        }
    }
    public UserInformation getUser() {
        return authUser;
    }


    public JSONObject saveError(Exception e, String explain) {
    	JSONObject jo = null;
    	try {
	        jo = JSONException.convertToJSON(e, explain);
	    	
	    	JSONException.traceConvertedException(System.out, jo);
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
	        return jo;
    	}
    	catch (Exception e2) {
    		JSONException.traceException(e2, "EXCEPTION while handling EXCEPTION . . . give up");
    	}
    	return jo;
    }
    public void clearError() {
        errMsg = new ArrayList<String>();
    }
    public List<String> getErrorList() {
        return errMsg;
    }


    public void startRegistration(String email) {
    	emailTested = email;
        emailConfirmed = false;
    }
    public void emailConfirmed(UserInformation ui) {
        authUser = ui;
        authIdentity = ui.emailAddress;
        emailTested  = ui.emailAddress;
        emailConfirmed = true;
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


    public JSONObject userStatusAsJSON(SSOFI ssofi) throws Exception {
        JSONObject jo = new JSONObject();
        jo.put("ss",  sessionId);
        jo.put("isLoggedIn", this.loggedIn());
        jo.put("isLDAP",   ssofi.isLDAPMode);
        jo.put("isLocal", !ssofi.isLDAPMode);
        
        JSONArray errors = new JSONArray();
        for (String msg : getErrorList()) {
            errors.put(msg);
        }
        jo.put("errors", errors);

        if (!loggedIn()) {
            jo.put("msg", "Not Logged In");
            jo.put("baseUrl", ssofi.baseURL);
            jo.put("presumedId", this.presumedId);
            return jo;
        }

        jo.put("msg",    "Logged In");
        jo.put("go",     return_to);
        jo.put("presumedId", this.presumedId);
        jo.put("userId", this.authIdentity);
        jo.put("user", authUser.getJSON());
        
        jo.put("emailConfirmed", this.emailConfirmed);

        return jo;
    }


    public void writeSessionToFile(File sessionFolder) throws Exception {
        JSONArray eList = new JSONArray();
        for (String em : errMsg) {
            eList.put(em);
        }

        JSONObject persistable = new JSONObject();
        if (authUser!=null) {
            //new way to store user info
            persistable = authUser.getJSON();

            //this is redundant.  I want to change to the fields above, however
            //I don't want to break any existing sessions.   Starting June 2021
            //we write the above AND below.  After July 2021 was can assume ALL
            //sessions have the above fields, and we can remove the below, as well
            //as change the fields that are read.
            persistable.put("authIdentity", authUser.userId);
            persistable.put("authName",     authUser.fullName);
            persistable.put("regEmail",     authUser.emailAddress);
        }
        persistable.put("presumedId",   presumedId);
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
            String uid = restored.optString("authIdentity");
            as.authIdentity = uid;
            if (uid!=null && uid.length()>0) {
                as.authUser = new UserInformation();
                as.authUser.userId = uid;
                as.authUser.fullName = restored.optString("authName");
                as.authUser.emailAddress = restored.optString("regEmail");
                as.emailTested = restored.optString("regEmail");
            }

            as.presumedId = restored.optString("presumedId");
            as.return_to = restored.optString("return_to");
            as.errMsg    = restored.getJSONArray("errMsg").getStringList();
            as.emailConfirmed = restored.optBoolean("emailConfirmed");
            return as;
        }
        else {
            as.writeSessionToFile(sessionFolder);
            System.out.println("SSOFI ("+sessionId+"): brand new session at "+currentTimeString());
        }
        return as;
    }



    //TODO: move this to a common location
    static final SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd-HH.mm.ss");
    public static String currentTimeString() {
        return dateFormatter.format(new Date());
    }

}
