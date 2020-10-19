package com.purplehillsbooks.ssofi;

import java.io.File;
import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;

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
    private ArrayList<String> errMsg = null;

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
    String regEmail;

    // When the user has successfully confirmed receipt of the magic
    // number at the specified email address and entered it.
    // then this will be marked true so we don't have to do it again.
    boolean regEmailConfirmed = false;

    Properties savedParams = new Properties();

    /**
     * this single hashtable holds many change/token pairs for all the users
     * It should be cleaned out periodically so that it does not grow forever.
     * It will be cleared on a reboot, hanging anyone attempting verification at that moment.
     * Verification is usually short: only a few seconds, so unlikely to be a problem.
     */
    private static Vector<ChallengeTokenEntry> challengeTokenMap = new Vector<ChallengeTokenEntry>();

    public AuthSession(String newSession) {
        sessionId = newSession;
    }

    public boolean loggedIn() {
        return authIdentity != null && authIdentity.length()>0;
    }

    public void login(String id, String name) {
        if (id==null || id.length()==0) {
            throw new RuntimeException("id value needs to be non-null during login");
        }
        authIdentity = id;
        if (name==null || name.length()==0) {
            throw new RuntimeException("Program Logic Error: null NAME passed at login time.  Why?");
        }
        authName = name;

        //This is the official log saying that someone logged in to the system
        System.out.println("SSOFI LOGIN: userId="+authIdentity+", name="+authName+", at "+currentTimeString());

        //we also wipe out any record of a previously sought after id, now that
        //you are logged in we don't need to remember who we thought you might be.
        presumedId = id;
    }

    public void logout() {
        //This is the official log saying that someone logged out of the system
        System.out.println("SSOFI LOGOUT: userId="+authIdentity+", name="+authName+", at "+currentTimeString());

        authIdentity = null;
        authName = null;
        regEmail = null;
        return_to = null;
    }

    public String loggedUserId() {
        return authIdentity;
    }

    public String loggedUserName() {
        return authName;
    }
    
    public void assureName() {
        if (authName==null || authName.length()==0) {
            authName = "User: "+authIdentity;
        }
    }
    

    public void saveError(Exception e) {
        ArrayList<String> newErrs = new ArrayList<String>();
        Throwable runner = e;
        while (runner!=null) {
            String msg = runner.toString();
            //strip off the class name if there is one
            if (msg.startsWith("java.lang.Exception")
                    || msg.startsWith("java.lang.RuntimeException")) {
                int pos = msg.indexOf(":");
                msg = msg.substring(pos+2);
            }
            int pos = msg.indexOf("nested exception");
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
        errMsg = null;
        savedParams.clear();
    }
    public ArrayList<String> getErrorList() {
        if (errMsg!=null) {
            return errMsg;
        }
        return new ArrayList<String>();
    }

    public void reinit(HttpServletRequest request) {
        return_to = request.getParameter("openid.return_to");
        presumedId = request.getParameter("openid.identity");
        if (presumedId==null) {
        	//get it from the cookie
        }
        errMsg = null;
    }

    public void startRegistration(String email) {
    	regEmail = email;
        regEmailConfirmed = false;
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


    /**
     * A token is generated and stored associated with the challenge.
     * This should be stored for a limited amount of time.
     * Actually, it will be stored as long as there is a session,
     * which could be a few hours, and it might be lost if the server
     * reboots.
     *
     * A challenge can only be used once to generate a token, and if used again
     * it cancels the token.  However, we don't remember the challenge after that
     * so if used again it is allowed.
     *
     * Also, picking up the verification also cancels the entry, so the same
     * challenge might be used again after verification.
     */
    String generateToken(String challenge) throws Exception {

        ChallengeTokenEntry cte = new ChallengeTokenEntry();
        cte.challenge = challenge;
        cte.authSession = this;
        cte.token = IdGenerator.createMagicNumber();
        cte.identity = authIdentity;
        cte.createdTime = System.currentTimeMillis();

        challengeTokenMap.add(cte);

        return cte.token;
    }

    /**
     * Verify that the token that matches the challenge has been given.
     * The token is also invalidated, so that you can not verify a second time.
     */
    public static synchronized AuthSession verifyToken(String identity, String challenge, String token) {

        Vector<ChallengeTokenEntry> stillRelevant = new Vector<ChallengeTokenEntry>();

        long tenMinutesAgo = System.currentTimeMillis() - 600000;
        AuthSession selected = null;
        for (ChallengeTokenEntry cte : challengeTokenMap) {
            if (cte.createdTime<tenMinutesAgo) {
                //ignore anything more than 10 minutes old
                continue;
            }
            if (challenge.equals(cte.challenge) && token.equals(cte.token)
                    && identity.equals(cte.identity)) {
                selected = cte.authSession;
            }
            else if (!challenge.equals(cte.challenge) && !token.equals(cte.token)) {
                //do not retain any entry where the challenge OR token match
                stillRelevant.add(cte);
            }
        }

        //replace the global map with the new one that omits timed-out entries
        //and also omits all token and challenge matches.
        challengeTokenMap = stillRelevant;

        return (selected);
    }

    private class ChallengeTokenEntry {
        public String challenge;
        public String token;
        public String identity;
        public AuthSession authSession;
        long createdTime;
    }


    public JSONObject userAsJSON() throws Exception {
        JSONObject persistable = new JSONObject();
        persistable.put("ss",  sessionId);
        if (this.loggedIn()) {
            persistable.put("userId",    authIdentity);
            persistable.put("userName",  authName);
            persistable.put("email",     regEmail);
            persistable.put("msg",       "Logged In");
        }
        else {
            persistable.put("msg", "Not Logged In");
        }
        return persistable;
    }

    
    public void writeSessionToFile(File sessionFolder) throws Exception {
        JSONObject persistable = new JSONObject();
        persistable.put("authIdentity", authIdentity);
        persistable.put("authName",     authName);
        persistable.put("presumedId",   presumedId);
        persistable.put("regEmail",     regEmail);
        persistable.put("return_to",    return_to);

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
            as.regEmail = restored.optString("regEmail");
            as.return_to = restored.optString("return_to");
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
