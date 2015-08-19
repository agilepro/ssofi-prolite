package org.workcast.ssofiprovider;

import java.io.Serializable;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Random;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;

import org.openid4java.message.ParameterList;

/**
 * Holds all the information that we need for a session
 */
public class AuthSession implements Serializable {

    private static final long serialVersionUID = 1L;

    ParameterList paramlist = null;

    // if something goes wrong, note it here for display next time
    Exception errMsg = null;

    // this is where the entire exchange will return to once done logging in
    String return_to;

    // this is the originally passed identity to VERIFY
    String identity;

    // this is the verified identity that the user is logged in as
    // null when use not logged in.
    private String authIdentity;

    // this is the verified identity that the user is logged in as
    // null when use not logged in.
    private String authName;

    // FOLLOWING THREE FIELDS FOR REGISTRATION OR RESETTING PASSWORD
    // This is the email address supplied by the user and tested
    // for registering a new email address.
    String regEmail;

    // This is the generated magic number which the user must receive
    // in the email address, and supply to prove that it was received
    String regMagicNo;

    // When the user has successfully confirmed receipt of the magic
    // number at the specified email address and entered it.
    // then this will be marked true so we don't have to do it again.
    boolean regEmailConfirmed = false;

    //QUICK mode is the user login and return without all the overhead of
    //open id.  Redirect with:
    //    openid.mode=quick&go=http://server/my/return/address
    //This will log the user in, and return to the specified URL
    //if the user is already logged in, it returns immediately
    boolean quickLogin = false;

    Properties savedParams = new Properties();

    /**
     * this single hashtable holds many change/token pairs for all the users
     * It should be cleaned out periodically so that it does not grow forever.
     * It will be cleared on a reboot, hanging anyone attempting verification at that moment.
     * Verification is usually short: only a few seconds, so unlikely to be a problem.
     */
    private static Vector<ChallengeTokenEntry> challengeTokenMap = new Vector<ChallengeTokenEntry>();

    public boolean loggedIn() {
        return authIdentity != null;
    }

    public void login(String id, String name) {
        authIdentity = id;
        if (name==null) {
            throw new RuntimeException("Program Logic Error: numm NAME passed at login time.  Why?");
        }
        authName = name;
    }

    public void logout() {
        authIdentity = null;
        authName = null;
        quickLogin = false;
    }

    public String loggedUserId() {
        return authIdentity;
    }

    public String loggedUserName() {
        return authName;
    }

    public void clearError() {
        errMsg = null;
        savedParams.clear();
    }

    public void reinit(HttpServletRequest request) {
        paramlist = new ParameterList(request.getParameterMap());
        return_to = request.getParameter("openid.return_to");
        identity = request.getParameter("openid.identity");
        errMsg = null;
    }

    public String startRegistration(String email) {
        regEmail = email;
        regMagicNo = createMagicNumber();
        regEmailConfirmed = false;
        return regMagicNo;
    }

    public void saveParameterList(HttpServletRequest request) {
        @SuppressWarnings("unchecked")
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

    private static String createMagicNumber() {
        Random rand = new Random();
        String nineLetters = IdGenerator.generateKey();
        StringBuffer betterNumber = new StringBuffer(20);
        betterNumber.append(nineLetters.substring(0, 3));
        betterNumber.append("-");
        betterNumber.append((char) ('A' + rand.nextInt(26)));
        betterNumber.append((char) ('A' + rand.nextInt(26)));
        betterNumber.append("-");
        betterNumber.append(nineLetters.substring(3, 6));
        betterNumber.append("-");
        betterNumber.append((char) ('A' + rand.nextInt(26)));
        betterNumber.append((char) ('A' + rand.nextInt(26)));
        betterNumber.append("-");
        betterNumber.append(nineLetters.substring(6, 9));
        return betterNumber.toString();
    }

    /**
     * return a copy of this object
     */
    public AuthSession copy() {
        AuthSession myCopy = new AuthSession();
        myCopy.errMsg = this.errMsg;
        myCopy.authIdentity = this.authIdentity;
        myCopy.authName = this.authName;
        myCopy.identity = this.identity;
        myCopy.paramlist = this.paramlist;
        myCopy.regEmail = this.regEmail;
        myCopy.regEmailConfirmed = this.regEmailConfirmed;
        myCopy.regMagicNo = this.regMagicNo;
        myCopy.return_to = this.return_to;
        myCopy.savedParams = this.savedParams;
        myCopy.quickLogin = this.quickLogin;
        return myCopy;
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
        cte.token = createMagicNumber();
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

}
