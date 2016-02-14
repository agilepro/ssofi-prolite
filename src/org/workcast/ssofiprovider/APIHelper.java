package org.workcast.ssofiprovider;

import java.io.Writer;

import javax.servlet.http.HttpServletResponse;

import org.workcast.json.JSONArray;
import org.workcast.json.JSONObject;

public class APIHelper {

	private JSONObject postedObject;
	private AuthSession aSession;
	private HttpServletResponse response;
	private EmailHandler emailHandler = null;
	private EmailTokenManager tokenManager;
	boolean destroySession = false;

	public APIHelper(AuthSession _aSession, JSONObject _postedObject, HttpServletResponse _response,
			EmailHandler _emailHandler, EmailTokenManager _tokenManager) {
		aSession     = _aSession;
		postedObject = _postedObject;
		response     = _response;
		emailHandler = _emailHandler;
		tokenManager = _tokenManager;
    }

    public boolean handleAPICommand(String mode) throws Exception {
        try {
        	JSONObject responseObj = getResponse(mode);
        	sendJSON(200, responseObj);
        }
        catch(Exception e) {
            System.out.println("SSOFI LAuth EXCEPTION: "+e.toString());
            e.printStackTrace(System.out);
            JSONObject jo = new JSONObject();
            JSONArray msgs = new JSONArray();
            Throwable t = e;
            while (t!=null) {
                msgs.put(t.toString());
                t = t.getCause();
            }
            jo.put("exception", msgs);
            sendJSON(200, jo);
        }
        return destroySession;
    }


    private JSONObject getResponse(String mode) throws Exception {
        System.out.println("SSOFI LAuth request: "+mode);
        //do not need to be logged in to verify a token
        if ("apiVerify".equals(mode)) {
            if (postedObject==null) {
                throw new Exception("Received a request for verifying a token without any posted JSON information");
            }
            String identity  = postedObject.getString("userId");
            String challenge = postedObject.getString("challenge");
            String token     = postedObject.getString("token");
            AuthSession auth = AuthSession.verifyToken(identity, challenge, token);
            if (auth!=null) {
                JSONObject responseObj = new JSONObject();
                responseObj.put("userId", auth.loggedUserId());
                String name = auth.loggedUserName();
                responseObj.put("userName", name);
                if (name==null || name.length()==0) {
                    responseObj.put("userName", "User: "+auth.loggedUserId());
                }
                responseObj.put("challenge", challenge);  //do we need this?
                responseObj.put("token", token);          //do we need this?
                responseObj.put("verified", true);
                responseObj.put("msg", "Token matches with the challenge");
                return responseObj;
            }
            else {
                postedObject.put("msg", "failure, the token does not match");
                postedObject.remove("userId");
                postedObject.remove("userName");
                postedObject.put("verified", false);
                return postedObject;
            }
        }
        if ("apiLogout".equals(mode)) {
            //whether you are logged in or not, you get the same response
            //from this command:  you are now logged out.
            aSession.logout();
            destroySession = true;
            JSONObject jo = new JSONObject();
            jo.put("msg", "User logged out");
            return jo;
        }
        if (!aSession.loggedIn()) {
            JSONObject jo = new JSONObject();
            jo.put("msg", "User not found, must be logged in to perform "+mode);
            return jo;
        }
        if ("apiWho".equals(mode)) {
            JSONObject jo = new JSONObject();
            jo.put("msg", "User logged in");
            jo.put("userId",   aSession.loggedUserId());
            jo.put("userName", aSession.loggedUserName());
            return jo;
        }
        if ("apiGenerate".equals(mode)) {
            if (postedObject==null) {
                throw new Exception("Received a request for generating a token without any posted JSON information");
            }
            String challenge = postedObject.getString("challenge");
            String token = aSession.generateToken(challenge);
            postedObject.put("userId",   aSession.loggedUserId());
            postedObject.put("userName", aSession.loggedUserName());
            postedObject.put("token",    token);
            return postedObject;
        }
        if ("apiSendInvite".equals(mode)) {
            if (postedObject==null) {
                throw new Exception("Received a request for sending email without any posted JSON information");
            }
            //remember, this user ID is NOT the logged in user who is requesting the invitation
            //but instead the user who is being sent the invitation.
            String userId = postedObject.getString("userId");
            String userName = postedObject.optString("userName");
            String msg = postedObject.getString("msg");
            String returnUrl = postedObject.getString("return");
            sendInviteEmail(userId, userName, msg, returnUrl);
            JSONObject okResponse = new JSONObject();
            okResponse.put("result", "ok");
            return okResponse;
        }
        throw new Exception("Authentication API can not understand mode "+mode);
    }


    private void sendInviteEmail(String userId, String userName, String msg, String returnUrl) throws Exception {
        if (!emailHandler.validate(userId)) {
            throw new Exception("The id supplied (" + userId
                    + ") does not appear to be a valid email address.");
        }
        String magicNumber = tokenManager.generateEmailToken(userId);
        emailHandler.sendInviteEmail(aSession.loggedUserId(), aSession.loggedUserName(), userId, msg, magicNumber, returnUrl);
    }


    private void sendJSON(int code, JSONObject jo) throws Exception {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(code);
        Writer out = response.getWriter();
        jo.write(out,2,0);
        out.flush();
    }

}
