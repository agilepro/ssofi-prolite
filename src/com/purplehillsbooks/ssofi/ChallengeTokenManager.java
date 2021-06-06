package com.purplehillsbooks.ssofi;

import java.util.Vector;

import com.purplehillsbooks.json.JSONObject;

/**
 * A token is associated with the challenge and a User.
 * This class manages the list of known associations.
 * Each entry is saved only ten minutes at most.
 *
 * This is not associated with any session, because the verification is delivered
 * to a server which has no login session.  Verification can be done by
 * any caller from any location.  Any party knowing both the challenge and
 * the token can verify they are associated, but only once.
 *
 * Once the challenge has been verified it is deleted and can not be used a second time.
 *
 * Since picking up the verification also cancels the entry, so the same
 * challenge might be used again after verification, however challenges
 * should be unique to avoid possible overlap requests.
 */
public class ChallengeTokenManager {

    private static class ChallengeTokenEntry {
        public String challenge;
        public String token;
        public UserInformation user;
        long createdTime;
    }

    /**
     * this single vector holds many challenge/token pairs for all authentication currently in flight
     * These associations only last ten minutes, and are not persisted on disk.
     * It will be cleared on a reboot, hanging anyone attempting verification at that moment.
     * Verification is usually short: only a few seconds, so unlikely to be a problem.
     */
    private static Vector<ChallengeTokenEntry> challengeTokenMap = new Vector<ChallengeTokenEntry>();


    /**
     * A token is generated and stored associated with the challenge and a User.
     * Also, any leftover old entries that are more than 10 minutes old are removed from the list.
     */
    public static synchronized String generateToken(String challenge, UserInformation user) throws Exception {

        ChallengeTokenEntry cte = new ChallengeTokenEntry();
        cte.challenge = challenge;
        cte.user = user;
        cte.token = IdGenerator.createMagicNumber();
        cte.createdTime = System.currentTimeMillis();

        challengeTokenMap.add(cte);

        return cte.token;
    }


    /**
     * Verify that the token that matches the challenge has been given
     * and if matched, return the authenticated user information that was
     * current at the time the token was generated.  The user might have
     * logged out, and back in as a different user, but this token is only
     * for the user at the time the token was generated.
     *
     * if no match is found, this returns null
     */
    public static synchronized UserInformation verifyToken(String challenge, String token) {

        Vector<ChallengeTokenEntry> stillRelevant = new Vector<ChallengeTokenEntry>();

        long tenMinutesAgo = System.currentTimeMillis() - 600000;
        UserInformation selected = null;
        for (ChallengeTokenEntry cte : challengeTokenMap) {
            if (cte.createdTime<tenMinutesAgo) {
                //ignore anything more than 10 minutes old
                continue;
            }
            if (challenge.equals(cte.challenge) && token.equals(cte.token)) {
                selected = cte.user;
            }
            else if (!challenge.equals(cte.challenge) && !token.equals(cte.token)) {
                //do not retain any entry where the challenge OR token match
                stillRelevant.add(cte);
            }
        }

        //replace the global map with the new one that omits timed-out entries
        //and also omits all token and challenge matches.
        challengeTokenMap = stillRelevant;

        //if no match was found, this returns null
        return selected;
    }


    public static JSONObject genVerifyObj(WebRequest wr) throws Exception {
        JSONObject postedObj = wr.getPostedObject();
        if (postedObj==null) {
            throw new Exception("Received a request for verifying a token without any posted JSON information");
        }
        String challenge = postedObj.getString("challenge");
        String token     = postedObj.getString("token");
        UserInformation user = ChallengeTokenManager.verifyToken(challenge, token);
        if (user!=null) {
            JSONObject responseObj = user.getJSON();
            responseObj.put("challenge", challenge);  //included so caller can identify request
            responseObj.put("token", token);          //included so caller can identify request
            responseObj.put("verified", true);
            responseObj.put("msg", "Token matches with the challenge, and user information returned");
            return responseObj;
        }
        else {
            JSONObject responseObj = new JSONObject();
            responseObj.put("challenge", challenge);  //included so caller can identify request
            responseObj.put("token", token);          //included so caller can identify request
            responseObj.put("verified", false);
            responseObj.put("msg", "Token does NOT match the challenge, so no user information returned");
            return responseObj;
        }
    }


    /**
     * implements the handling of the protocol with JSONObjects in and out
     */
    public static void handleVerifyRequest(WebRequest wr) {
        try {
            JSONObject responseObj = genVerifyObj(wr);
            wr.streamJSON(responseObj);
        }
        catch (Exception e) {
            Exception wrapper = new Exception("Failure while trying to verify that token matches with challenge", e);
            wr.streamException(wrapper);
        }
    }


}
