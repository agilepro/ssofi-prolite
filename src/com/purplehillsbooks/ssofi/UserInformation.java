package com.purplehillsbooks.ssofi;

import com.purplehillsbooks.json.JSONObject;

/**
 * This is just a package for all the information about a user we might need.
 * Add fields if there is additional information for display.
 */
public class UserInformation {

    public boolean alreadyInFile = false;
    public boolean hasPassword = true;
    public String uniqueKey;
    public String userId;
    public String fullName;
    public String emailAddress;


    public JSONObject getJSON() throws Exception {
        JSONObject jo = new JSONObject();
        jo.put("userId",    userId);
        jo.put("userName",  fullName);
        jo.put("email",     emailAddress);
        jo.put("source",    "UI:"+userId);
        return jo;
    }

}
