package com.purplehillsbooks.ssofi;

import java.io.Writer;
import java.util.Properties;

import com.purplehillsbooks.json.SimpleException;
import com.purplehillsbooks.json.JSONObject;

public class APIHelper {

	private WebRequest wr;
	private AuthSession aSession;
    private JSONObject postedObject;
    private SSOFI ssofi;
	boolean destroySession = false;

	public static String baseURL;

	public APIHelper(AuthSession _aSession, WebRequest _wr,SSOFI _ssofi) throws Exception {
	    wr           = _wr;
		aSession     = _aSession;
		postedObject = wr.getPostedObject();
		ssofi        = _ssofi;
    }


	public JSONObject login() throws Exception {
        aSession.clearError();
        // this takes the action of logging the user in, and returning if all OK
        // first see if they pressed the Cancel key
        String userId = postedObject.getString("userId");
        String password = postedObject.getString("password");

        //if already logged in
        if (aSession.loggedIn()) {
            if (aSession.loggedUserId().equalsIgnoreCase(userId)) {
                //if already to this particular name, then don't change anything
                return aSession.userStatusAsJSON(ssofi);
            }
            else {
                //since the name changed, log out just to be sure
                aSession.logout();
            }
        }

        if (!ssofi.authStyle.authenticateUser(userId, password)) {
            throw new Exception("Unable to log you in to user id (" + userId
                    + ") with that password.  Please try again or reset your password.");
        }

        UserInformation ui = ssofi.authStyle.getOrCreateUser(userId);
        aSession.setUserOnSession(ui);
        ssofi.sHand.saveAuthSession(aSession);

        // This is a 'low security' cookie.  It keeps the Id of the usr
        // that successfully logged in so that next time we can
        // remember and save the user having to type in again.
        // But there is no security value here.
        wr.setCookie("SSOFIUser", userId);
        aSession.presumedId = userId;
        return aSession.userStatusAsJSON(ssofi);
    }


	public JSONObject logout() throws Exception {
        aSession.clearError();
        String formerUser = "not-logged-in";
        //whether you are logged in or not, you get the same response
        //from this command:  you are now logged out.
        if (aSession.loggedIn()) {
            formerUser = aSession.loggedUserId();
            aSession.logout();

            //this deletes the file if there is one
            ssofi.sHand.deleteAuthSession(aSession.sessionId);

            //this changes it session ID so that all new interactions are on a new ID
            aSession.changeSessionId(SSOFI.createSSOFISessionId(wr));
            ssofi.sHand.saveAuthSession(aSession);
        }
        System.out.println("SSOFI ("+aSession.sessionId+"): logout successful, previous user was: "+formerUser+" at "+AuthSession.currentTimeString());
        return aSession.userStatusAsJSON(ssofi);
	}

	public JSONObject whoAmI() throws Exception {

        String formerUser = "not-logged-in";
        if (aSession.loggedIn()) {
            formerUser = aSession.loggedUserId();
        }
        JSONObject rrr = aSession.userStatusAsJSON(ssofi);
        System.out.println("SSOFI ("+aSession.sessionId+"): apiWho confirmation of user: "+formerUser+" at "+AuthSession.currentTimeString());
        return rrr;
    }


	public JSONObject setPassword() throws Exception {
        aSession.clearError();
        try {
            if (!aSession.loggedIn()) {
                System.out.println("SSOFI ERROR: attempt to change password when not logged in: "+aSession.sessionId);
                throw new Exception("You can not change a password when you are not logged in.  Maybe your session timed out? at "+AuthSession.currentTimeString());
            }
            if (postedObject==null) {
                throw new Exception("to change a password there must be a posted JSON object");
            }
            UserInformation userInfo = null;
            if (aSession.hasJustConfirmed()) {
                //just call this to make sure that the user object exists in the file
                userInfo = ssofi.authStyle.getOrCreateUser(aSession.emailTested);
            }
            else {
                userInfo = ssofi.authStyle.getExistingUserOrNull(aSession.loggedUserId());
                if (userInfo == null) {
                    throw new SimpleException("Unable to set password because user %s does not exist, and email has not been confirmed.", aSession.emailTested);
                }
                String oldPwd = postedObject.optString("oldPwd");
                if (oldPwd==null) {
                    throw new Exception("Must pass 'oldPwd' when setting password, and when you have not just confirmed the email address.");
                }
                if (!ssofi.authStyle.authenticateUser(aSession.loggedUserId(), oldPwd)) {
                    throw new SimpleException("The 'oldPwd' submitted does not appear to be the correct one for user %s", aSession.emailTested);
                }
            }

            String newPwd = postedObject.getString("newPwd");
            ssofi.authStyle.setPassword(aSession.loggedUserId(), newPwd);
            aSession.clearConfirmBit();
            ssofi.sHand.saveAuthSession(aSession);

            System.out.println("SSOFI ("+aSession.sessionId+"): setPassword successful for user: "+aSession.loggedUserId()+" at "+AuthSession.currentTimeString());
            return aSession.userStatusAsJSON(ssofi);
        }
        catch (Exception e) {
            throw new SimpleException("Unable to set password for user (%s)",  e, aSession.loggedUserId());
        }
    }



	public JSONObject setName() throws Exception {
        aSession.clearError();
        try {
            if (!aSession.loggedIn()) {
                System.out.println("SSOFI ERROR: attempt to change name when not logged in: "+aSession.sessionId);
                throw new Exception("You can not set your name when you are not logged in.  Maybe your session timed out?");
            }
            if (postedObject==null) {
                throw new Exception("To change a name there must be a posted JSON object.");
            }
            if (aSession.hasJustConfirmed()) {
                //this might be the very first save, so create user if necessary
                ssofi.authStyle.getOrCreateUser(aSession.loggedUserId());
            }
            String fullName = postedObject.getString("fullName");
            ssofi.authStyle.changeFullName(aSession.loggedUserId(), fullName);
            aSession.updateFullName(fullName);
            ssofi.sHand.saveAuthSession(aSession);
            System.out.println("SSOFI ("+aSession.sessionId+"): setName successful for user: "+aSession.loggedUserId()+" at "+AuthSession.currentTimeString());
            return aSession.userStatusAsJSON(ssofi);
        }
        catch (Exception e) {
            throw new SimpleException("Unable to set name for user %s",  e, aSession.loggedUserId());
        }
    }



	public JSONObject sendPasswordReset() throws Exception {
        aSession.clearError();
        if (postedObject==null) {
            throw new Exception("Received a request for sending email without any posted JSON information");
        }
        String registerEmail = postedObject.getString("registerEmail").trim();
        if (!ssofi.emailHandler.validAddressFormat(registerEmail)) {
            throw new Exception("The id supplied (" + registerEmail
                    + ") does not appear to be a valid email address.");
        }

        // Security check
        Properties secProp = new Properties();
        secProp.put(SecurityHandler.REGIS_REQ_REMOTE_IP, wr.request.getRemoteAddr());
        secProp.put(SecurityHandler.REGIS_REQ_EMAILID, registerEmail);
        secProp.put(SecurityHandler.CAPTCHA_CHALLANGE_REQ,
                wr.defParam(SecurityHandler.CAPTCHA_CHALLANGE_REQ, ""));
        secProp.put(SecurityHandler.CAPTCHA_CHALLANGE_RESP,
                wr.defParam(SecurityHandler.CAPTCHA_CHALLANGE_RESP, ""));


        //this appears to only check the Captcha
        ssofi.securityHandler.validate(secProp);


        aSession.presumedId = registerEmail;

        String magicNumber = ssofi.tokenManager.generateEmailToken(registerEmail);
        aSession.startRegistration(registerEmail);
        ssofi.emailHandler.sendVerifyEmail(registerEmail, magicNumber, aSession.return_to, ssofi.baseURL);
        ssofi.sHand.saveAuthSession(aSession);
        System.out.println("SSOFI ("+aSession.sessionId+"): email password reset sent for user: "+registerEmail+" at "+AuthSession.currentTimeString());
        return aSession.userStatusAsJSON(ssofi);
    }




	public JSONObject generateToken() throws Exception {
        aSession.clearError();
        if (!aSession.loggedIn()) {
        	//this is an unusual situation, make noise
            System.out.println("SSOFI: attempt to generate token when not logged in: "+aSession.sessionId+" at "+AuthSession.currentTimeString());
            throw new Exception("You can not generate a token when you are not logged in.  Maybe your session timed out?");
        }
        if (postedObject==null) {
            throw new Exception("Received a request for generating a token without any posted JSON information");
        }
        UserInformation user = aSession.getUser();

        String challenge = postedObject.getString("challenge");
        String token = ChallengeTokenManager.generateToken(challenge, user);

        JSONObject responseObj = user.getJSON();
        responseObj.put("ss",         aSession.sessionId);
        responseObj.put("challenge",  challenge);
        responseObj.put("token",      token);
        responseObj.put("msg",        "token has been generated, now give this to the server to authenticate");
        System.out.println("SSOFI ("+aSession.sessionId+"): token generated for user: "+aSession.loggedUserId()+" at "+AuthSession.currentTimeString());
        return responseObj;
    }

	public boolean handleAPICommand(String mode) throws Exception {
        try {
        	JSONObject responseObj = getResponse(mode);
        	sendJSON(200, responseObj);
        }
        catch(Exception e) {
            JSONObject jo = aSession.saveError(e, "Unable to handle SSOFI request for "+mode);
            ssofi.sHand.saveAuthSession(aSession);
            sendJSON(400, jo);
        }
        return destroySession;
    }


    private JSONObject getResponse(String mode) throws Exception {
        if ("apiVerify".equals(mode)) {
            throw new Exception("apiVerify should have already been handled at higher level!");
        }
        if ("apiLogout".equals(mode)) {
            return logout();
        }
        if ("apiWho".equals(mode)) {
            return whoAmI();
        }
        if ("apiSendInvite".equals(mode)) {
            return sendInvite();
        }
        //do not need to be logged in to verify a token, to log out or to ask whether logged in
        //do need to be logged in to send an email or to generate a token
        if (!aSession.loggedIn()) {
            System.out.println("SSOFI ("+aSession.sessionId+"): not logged in, not allowed: "+mode+" at "+AuthSession.currentTimeString());
            return aSession.userStatusAsJSON(ssofi);
        }
        if ("apiGenerate".equals(mode)) {
            return generateToken();
        }
        System.out.println("SSOFI ("+aSession.sessionId+") UNRECOGNISED MODE: "+mode+" - "+aSession.loggedUserId()+" at "+AuthSession.currentTimeString());
        throw new SimpleException("Authentication API can not understand mode %s", mode);
    }

    static long nextInviteTime = System.currentTimeMillis();
    public JSONObject sendInvite() throws Exception {
        aSession.clearError();
        if (postedObject==null) {
            throw new Exception("Received a request for sending invite email without any posted JSON information");
        }
        String inviteeId = postedObject.getString("userId");
        if (inviteeId == null || inviteeId.length()==0) {
            throw new Exception("Posted object does not contain a 'userId' value to send invite to");
        }
            
        try {
            //because this API is allowed without being authenticated, throttle to make sure it can not
            //be used to send thousands of emails.
            long waitTime = nextInviteTime-System.currentTimeMillis();
            if (waitTime>0) {
                nextInviteTime = nextInviteTime + 10000;   //10 seconds minimum between calls
                Thread.sleep(waitTime);
            }
            else {
                nextInviteTime = System.currentTimeMillis() + 10000;   //10 seconds minimum between calls
            }
            
            //remember, this user ID is NOT the logged in user who is requesting the invitation
            //but instead the user who is being sent the invitation.
            String inviteeName = postedObject.optString("userName");
            String msg = postedObject.getString("msg");
            String returnUrl = postedObject.getString("return");
            String subject = postedObject.optString("subject", "Invitation to Collaborate");
            sendInviteEmail(inviteeId, inviteeName, msg, returnUrl, subject, baseURL);
            JSONObject okResponse = new JSONObject();
            okResponse.put("result", "ok");
            okResponse.put("userId", inviteeId);
            System.out.println("SSOFI ("+aSession.sessionId+"): email invite sent for user: "+aSession.loggedUserId()+" at "+AuthSession.currentTimeString());
            return okResponse;
        }
        catch (Exception e) {
            throw new SimpleException("Unable to send invite message to %s", inviteeId);
        }
    }

    private void sendInviteEmail(String userId, String userName, String msg, String returnUrl, String subject, String baseURL) throws Exception {
        if (!ssofi.emailHandler.validAddressFormat(userId)) {
            throw new SimpleException("The id supplied (%s) does not appear to be a valid email address.", userId);
        }
        //The idea here is to slow down any attempt to send email.
        //one user to wait 3 seconds is not a problem, but this will
        //significantly slow down a hacker
        Thread.sleep(3000);
        String magicNumber = ssofi.tokenManager.generateEmailToken(userId);
        
        String fromName = "Weaver";
        if (aSession.loggedIn()) {
            //new email sender SMTP2GO does not allow this from address that is not verified
            //fromAddress = aSession.loggedUserId();
            fromName = aSession.loggedUserName();
        }
        ssofi.emailHandler.sendInviteEmail(fromName, userId, msg, subject, magicNumber, returnUrl, baseURL);
    }


    private void sendJSON(int code, JSONObject jo) throws Exception {
        wr.response.setContentType("application/json;charset=UTF-8");
        wr.response.setStatus(code);
        Writer out = wr.w;
        jo.write(out,2,0);
        out.flush();
    }

}
