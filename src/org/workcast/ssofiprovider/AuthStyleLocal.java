package org.workcast.ssofiprovider;

import java.io.File;
import java.util.Vector;

import javax.servlet.ServletContext;

import org.workcast.mendocino.Mel;

/**
 * Collect all the local specific functionality into this class
 */
public class AuthStyleLocal implements AuthStyle {

    private Mel users = null;
    private File userFile;
    private Vector<User> userList;
    private long timestampLastRead = 0;
    private String[] overridePasswords;
    private boolean makeUpUsers = false;

    public AuthStyleLocal(ServletContext sc, SSOFI ssofi) throws Exception {

        File dataFolder = ssofi.getDataFolder();

        userFile = new File(dataFolder, "users.xml");
        if (!userFile.exists()) {
            ssofi.initFileFromWebInf(userFile);
        }

        // handle override passwords, if any. You can specify any number
        // of passwords separated by semicolons. The passwords themselves
        // can not have a semicolon in them. e.g.
        // overridePassword=pass1;pass2;pass3
        String opass = ssofi.getSystemProperty("overridePassword");
        if (opass == null) {
            overridePasswords = new String[0];
        }
        else {
            overridePasswords = opass.trim().split(";");
            makeUpUsers = true;
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
            userList = new Vector<User>();
            for (User u : users.getChildren("user", User.class)) {
                userList.add(u);
            }
        }
        catch (Exception e) {
            throw new Exception("Unable to access user file ("+userFile+")",e);
        }

    }

    public String getStyleIndicator() {
        return "local";
    }

    public boolean authenticateUser(String userNetId, String userPwd) throws Exception {

        // handle override (dummy) case
        for (String possible : overridePasswords) {
            if (possible.equals(userPwd)) {
                return true;
            }
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

    public UserInformation getOrCreateUser(String searchEmail) throws Exception {
        UserInformation uret = new UserInformation();

        User foundUser = searchUsersByAny(searchEmail);

        if (foundUser == null) {
            uret.key = User.generateKey();
            uret.emailAddress = searchEmail;
            uret.fullName = "User "+searchEmail;
            uret.hasPassword = false;
            if (makeUpUsers) {
                // generates a user record for any email address, just based on
                // email address
                uret.exists = true;
            }
            else {
                uret.exists = false;
            }
        }
        else {
            uret.key = foundUser.getKey();
            uret.exists = true;
            uret.fullName = foundUser.getFullName();
            uret.emailAddress = foundUser.getEmailMatchingSearchTerm(searchEmail);
            String password = foundUser.getPassword();
            uret.hasPassword = (password!=null && password.length()>0);
        }
        System.out.println("FOUND: name="+uret.fullName+", key="+uret.key+", email="+uret.emailAddress);
        return uret;
    }

    public void setPassword(String userId, String newPwd) throws Exception {
        User foundUser = searchUsersByAny(userId);
        if (foundUser == null) {
            throw new Exception("Internal consistency error: unable to find user record for: "
                    + userId);
        }
        foundUser.setPassword(PasswordEncrypter.getSaltedHash(newPwd));
        saveUserFile();
    }

    private void saveUserFile() throws Exception {

        users.reformatXML();
        users.writeToFile(userFile);
        timestampLastRead = userFile.lastModified();
    }

    public void changePassword(String userId, String oldPwd, String newPwd) throws Exception {
        User foundUser = searchUsersByAny(userId);
        if (foundUser == null) {
            throw new Exception("Internal consistency error: unable to find user record for: "
                    + userId);
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
            throw new Exception("Internal consistency error: unable to find user record for: "
                    + userId);
        }
        String oldName = foundUser.getFullName();
        if (!oldName.equals(newName)) {
            foundUser.setFullName(newName);
            saveUserFile();
        }
    }

    public boolean isAdmin(String userId) {
        User foundUser = searchUsersByAny(userId);
        return foundUser.getAdmin();
    }

    public void updateUserInfo(UserInformation userInfo, String newPwd) throws Exception {
        User userRec = searchUsersByAny(userInfo.key);
        if (overridePasswords.length>0) {
            throw new Exception("This local SSOFI provider is configured in test mode with a single password for all users.  You can't actually set a new password for a single user.  Simply use the predefined password.");
        }
        else if (userRec == null) {
            if (userInfo.exists) {
                throw new Exception(
                        "Don't understand attempt to update a profile that does not exist.  Clear the exist flag to false when you want to create a new profile.");
            }
            userRec = users.addChild("user", User.class);
            userRec.setKey(userInfo.key);
        }
        else if (!userInfo.exists) {
            throw new Exception(
                    "Don't understand attempt to create a new profile when one with id="+userInfo.key+" already exists.  Set the exist flag to update existing profile.");
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
        userList.removeAllElements();
        userList.addAll(users.getChildren("user", User.class));
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
