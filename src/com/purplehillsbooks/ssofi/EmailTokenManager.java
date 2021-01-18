package com.purplehillsbooks.ssofi;

import java.io.File;

import com.purplehillsbooks.json.JSONArray;
import com.purplehillsbooks.json.JSONObject;

/**
 * When sending a message to verify an email address, along with the message
 * you send a token.  That token is random, and long enough to be hard to guess.
 * The token is good for a limited amount of time, like 24 hours.  And the token
 * can only be used once, to avoid the problem of someone reusing the token and
 * changing someone else's password just after they set it.
 *
 * This class keeps a set of email to token associations as a file.  The EmailTokenManager
 * needs to be created, and the file is read at that time.  Then, for every change, the
 * file must be saved.  Tokens are verified and consumed, meaning they are deleted
 * as they are verified.   Token more than 24 hours old are discarded.
 *
 * We allow multiple, overlapping tokens on the same email address.  The reason is that
 * it is easy for the user to accidentally send the email twice ... especially if the
 * sending email server is quite slow.  The user may click the button twice.
 * Then, the user is confused about which of the two email messages to use.
 * They probably will use the first email message, even if the second is coming.
 * The easiest solution is to consider each token valid for the time period it is
 * valid (24 hours) without regard to how many tokens have been requested.
 * Any one of those tokens returned means that the person who clicked had access to
 * the email inbox, so consider them validated even it was not the latest token sent.
 *
 * It should be obvious that we never want to resend the same token again.
 */
public class EmailTokenManager {

	File filePath;
	JSONObject tokenFile;

	public EmailTokenManager(File tokenFilePath) throws Exception {
		filePath = tokenFilePath;
		if (tokenFilePath.exists()) {
			tokenFile = JSONObject.readFromFile(filePath);
		}
		else {
			//bootstrap: if it never existed, create it
			tokenFile = new JSONObject();
			tokenFile.put("list", new JSONArray());
			save();
		}
	}

	private void save() throws Exception {
		tokenFile.writeToFile(filePath);
	}

	private JSONArray getCurrentItems() throws Exception {
		long eightDaysAgo = System.currentTimeMillis() - 8L*24*60*60*1000;
		JSONArray list = tokenFile.getJSONArray("list");
		JSONArray filteredList = new JSONArray();
		for (int i=0; i<list.length(); i++) {
			JSONObject listItem = list.getJSONObject(i);
			long timestamp = listItem.getLong("timestamp");
			if (timestamp<eightDaysAgo)  {
				continue;
			}
			filteredList.put(listItem);
		}
		return filteredList;
	}

	public synchronized String generateEmailToken(String emailAddress) throws Exception {
		String token = IdGenerator.createMagicNumber();
		JSONArray list = getCurrentItems();
		JSONObject newItem = new JSONObject();
		newItem.put("timestamp", System.currentTimeMillis());
		newItem.put("email", emailAddress);
		newItem.put("token", token);
		list.put(newItem);
		tokenFile.put("list", list);
		save();
		return token;
	}

	public synchronized boolean validateAndConsume(String email, String token) throws Exception {
		long lastWeek = System.currentTimeMillis() - 7L*24*60*60*1000;
		JSONArray list = tokenFile.getJSONArray("list");
		JSONArray filteredList = new JSONArray();
		boolean foundIt = false;
		for (int i=0; i<list.length(); i++) {
			JSONObject listItem = list.getJSONObject(i);
			long timestamp = listItem.getLong("timestamp");
			if (timestamp<lastWeek)  {
			    //skip the outdated ones
				continue;
			}
			String thisEmail = listItem.getString("email");
			if (email.equals(thisEmail)) {
				String thisToken = listItem.getString("token");
			    if (thisToken.equals(token)) {
			    	foundIt = true;
			    	System.out.println("SSOFI: validated email token and removed: "+token);
			    	continue;   //don't save this now it is found
			    }
			}
			filteredList.put(listItem);
		}
		tokenFile.put("list", filteredList);
		save();
		return foundIt;
	}
}
