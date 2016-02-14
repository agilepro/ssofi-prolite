package org.workcast.ssofiprovider;

import org.workcast.json.JSONObject;

/**
 * This is just a package for all the information about a user we might need.
 * Add fields if there is additional information for display.
 */
public class UserInformation {

    public boolean exists = false;
    public boolean hasPassword = true;
    public String key;
    public String fullName;
    public String emailAddress;
    public String directoryName;

    public JSONObject getJSON() throws Exception {
        JSONObject jo = new JSONObject();
        jo.put("userName",  fullName);
        jo.put("userId",    emailAddress);
        jo.put("userKey",   key);
        return jo;
    }

}
