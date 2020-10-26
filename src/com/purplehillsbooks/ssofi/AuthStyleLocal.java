package com.purplehillsbooks.ssofi;

import java.io.File;
import java.util.Vector;

import javax.servlet.ServletContext;

import com.purplehillsbooks.json.JSONException;
import com.purplehillsbooks.xml.Mel;

/**
 * Collect all the local specific functionality into this class
 */
public class AuthStyleLocal implements AuthStyle {

    private Mel users = null;
    private File userFile;
    private Vector<User> userList = new Vector<User>();
    private long timestampLastRead = 0;
    private boolean ignorePasswordMode = false;

    public AuthStyleLocal(ServletContext sc, SSOFI ssofi) throws Exception {

        File dataFolder = ssofi.getDataFolder();

        userFile = new File(dataFolder, "users.xml");
        if (!userFile.exists()) {
            ssofi.initFileFromWebInf(userFile);
        }

        // ignore passwords mode allows for testing sitautions
        // where people login and out of multiple users frequently
        // passwords are accepted without testing them.
        ignorePasswordMode = "yes".equalsIgnoreCase(ssofi.getSystemProperty("ignorePassword"));
        if (ignorePasswordMode) {
            System.out.println("SSOFI:  ignore password mode -- all passwords will be accepted without testing");
        }

        refreshUserInfo();
    }

    public void refreshUserInfo() throws Exception {

        try {
            if (userFile.exists()) {
                // if the file is no newer than last time we read it, then there
                // is no reason to read it. We already have the current info.
                if (timestampLastRead >= userFile.lastModified()) {
                    return;
                }
                users = Mel.readFile(userFile, Mel.class);
            }
            else {
                users = Mel.createEmpty("users", Mel.class);
                users.writeToFile(userFile);
            }

            timestampLastRead = userFile.lastModified();
            userList.clear();
            userList.addAll(users.getChildren("user", User.class));
        }
        catch (Exception e) {
            throw new JSONException("Unable to access user file ({0})", e, userFile);
        }

    }

    public String getStyleIndicator() {
        return "local";
    }

    public boolean authenticateUser(String userNetId, String userPwd) throws Exception {

        if (ignorePasswordMode) {
            return true;
        }

        // handle real, encrypted case
        User foundUser = searchUsersByAny(userNetId);
        if (foundUser != null) {
            String storedHash = foundUser.getPassword();

            // transition hack ... the encrypted versions are long, but use it
            // as a non encrypted  password if it is short. This allows a tester
            // to set up a file for testing.
            // But in practice no short passwords will be created by the system
            if (storedHash.length() < 24) {
                return userPwd.equals(storedHash);
            }
            return PasswordEncrypter.check(userPwd, storedHash);
        }
        return false;
    }

    public UserInformation getExistingUserOrNull(String searchEmail) throws Exception {
        if (searchEmail==null) {
            throw new Exception("Program-Logic-Error: getOrCreateUser called with null searchEmail");
        }

        User foundUser = searchUsersByAny(searchEmail);
        if (foundUser == null) {
            return null;
        }

        UserInformation uret = new UserInformation();
        uret.key = foundUser.getKey();
        uret.alreadyInFile = true;
        uret.fullName = foundUser.getFullName();
        uret.emailAddress = foundUser.getEmailMatchingSearchTerm(searchEmail);
        String password = foundUser.getPassword();
        uret.hasPassword = (password!=null && password.length()>0);
        return uret;
    }

    public UserInformation getOrCreateUser(String searchEmail) throws Exception {

        UserInformation uret = getExistingUserOrNull(searchEmail);
        if (uret!=null) {
            return uret;
        }

        uret = new UserInformation();
        uret.key = User.generateKey();
        uret.emailAddress = searchEmail;
        uret.fullName = "";
        uret.hasPassword = false;
        uret.alreadyInFile = false;

        //now actually create the user
        User userRec = users.addChild("user", User.class);
        userRec.setKey(uret.key);
        userRec.addAddress(searchEmail);
        saveUserFile();

        System.out.println("SSOFI: CREATED NEW USER RECORD: name="+uret.fullName+", key="+uret.key+", email="+uret.emailAddress);
        return uret;
    }

    public void setPassword(String userId, String newPwd) throws Exception {
        User foundUser = searchUsersByAny(userId);
        if (foundUser == null) {
            throw new JSONException("Internal consistency error: unable to find user record for: {0}", userId);
        }
        foundUser.setPassword(PasswordEncrypter.getSaltedHash(newPwd));
        saveUserFile();
    }

    private void saveUserFile() throws Exception {

        users.reformatXML();
        users.writeToFile(userFile);
        timestampLastRead = userFile.lastModified();
        userList.removeAllElements();
        userList.addAll(users.getChildren("user", User.class));
    }

    public void changePassword(String userId, String oldPwd, String newPwd) throws Exception {
        User foundUser = searchUsersByAny(userId);
        if (foundUser == null) {
            throw new JSONException("Internal consistency error: unable to find user record for: {0}", userId);
        }
        String storedHash = foundUser.getPassword();
        // transition hack ... the encrypted versions are long, but use it as a
        // non encrypted
        // password if it is short. This allows a tester to set up a file for
        // testing.
        // But in practice no short passwords will be created by the system
        if (storedHash.length() < 24) {
            if (!oldPwd.equals(storedHash)) {
                throw new Exception(
                        "Unable to change password to new value, because old password value did not match our records.");
            }
        }
        else if (!PasswordEncrypter.check(oldPwd, storedHash)) {
            throw new Exception(
                    "Unable to change password to new value, because old password value did not match our records.");
        }
        foundUser.setPassword(PasswordEncrypter.getSaltedHash(newPwd));
        saveUserFile();
    }

    public void changeFullName(String userId, String newName) throws Exception {
        User foundUser = searchUsersByAny(userId);
        if (foundUser == null) {
            throw new JSONException("Internal consistency error: unable to find user record for: {0}", userId);
        }
        String oldName = foundUser.getFullName();
        if (!oldName.equals(newName)) {
            foundUser.setFullName(newName);
            saveUserFile();
        }
    }


    public void updateUserInfo(UserInformation userInfo, String newPwd) throws Exception {
        User userRec = searchUsersByAny(userInfo.key);
        if (userRec == null) {
            if (userInfo.alreadyInFile) {
                throw new Exception("Don't understand attempt to update a profile that does not exist.  "
                        +"Clear the 'alreadyInFile' flag to false when you want to create a new profile.");
            }
            //now actually create the user
            userRec = users.addChild("user", User.class);
            userRec.setKey(userInfo.key);
        }
        else if (!userInfo.alreadyInFile) {
            throw new JSONException(
                    "Don't understand attempt to create a new profile when one with id={0} already exists.  Set the exist flag to update existing profile.", userInfo.key);
        }
        userRec.setFullName(userInfo.fullName);
        if (userInfo.emailAddress!=null) {
            stripEmailFromAllOtherUsers(userInfo);
            userRec.addAddress(userInfo.emailAddress);
        }
        if (newPwd != null) {
            userRec.setPassword(PasswordEncrypter.getSaltedHash(newPwd));
        }
        saveUserFile();
    }

    private User searchUsersByAny(String userNetId) {

        for (User oneUser : userList) {
            if (oneUser.hasEmail(userNetId)) {
                return oneUser;
            }
            if (userNetId.equals(oneUser.getKey())) {
                return oneUser;
            }
        }
        return null;
    }

    /**
     * Runs through all the users *except* the one passed in, and makes
     * sure that those users do not have the specified email address.
     * User to guarantee that each user record has unique email addresses.
     */
    private void stripEmailFromAllOtherUsers(UserInformation userInfo) throws Exception {
        for (User oneUser : userList) {
            if (userInfo.key.equals(oneUser.getKey())) {
                //skip the currently interesting user
                continue;
            }
            oneUser.removeAddress(userInfo.emailAddress);
        }
    }

    public String searchForID(String searchTerm) throws Exception {

        // first check if there is a user with an exact match
        for (User oneUser : userList) {
            if (oneUser.hasEmail(searchTerm)) {
                return searchTerm;
            }
        }

        // did not find an exact match, then search for partial strings
        for (User oneUser : userList) {
            if (oneUser.hasEmailMatchingSearchTerm(searchTerm)) {
                return oneUser.getEmailMatchingSearchTerm(searchTerm);
            }
        }

        return null;
    }

}
