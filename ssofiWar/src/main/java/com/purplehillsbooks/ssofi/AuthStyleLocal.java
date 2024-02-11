package com.purplehillsbooks.ssofi;

import java.io.File;
import java.util.ArrayList;
import jakarta.servlet.ServletContext;

import com.purplehillsbooks.json.SimpleException;
import com.purplehillsbooks.xml.Mel;

/**
 * Collect all the local specific functionality into this class
 */
public class AuthStyleLocal implements AuthStyle {

    private Mel users = null;
    private File userFile;
    private ArrayList<StoredUser> userList = new ArrayList<StoredUser>();
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
            userList.addAll(users.getChildren("user", StoredUser.class));
        }
        catch (Exception e) {
            throw new SimpleException("Unable to access user file (%s)", e, userFile.getAbsolutePath());
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
        StoredUser foundUser = searchUsersByAny(userNetId);
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

        StoredUser foundUser = searchUsersByAny(searchEmail);
        if (foundUser == null) {
            return null;
        }

        UserInformation uret = new UserInformation();
        uret.uniqueKey = foundUser.getKey();
        uret.alreadyInFile = true;
        uret.fullName = foundUser.getFullName();
        uret.emailAddress = foundUser.getEmail();
        uret.userId = uret.emailAddress;
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
        uret.uniqueKey = StoredUser.generateKey();
        uret.userId = searchEmail;
        uret.emailAddress = searchEmail;
        uret.fullName = "";
        uret.hasPassword = false;
        uret.alreadyInFile = false;

        //now actually create the user
        StoredUser userRec = users.addChild("user", StoredUser.class);
        userRec.setKey(uret.uniqueKey);
        userRec.setEmail(searchEmail);
        saveUserFile();

        System.out.println("SSOFI: CREATED NEW USER RECORD: name="+uret.fullName+", userId="+uret.userId+", email="+uret.emailAddress);
        return uret;
    }

    public void setPassword(String userId, String newPwd) throws Exception {
        StoredUser foundUser = searchUsersByAny(userId);
        if (foundUser == null) {
            throw new SimpleException("Internal consistency error: unable to find user record for: %s", userId);
        }
        foundUser.setPassword(PasswordEncrypter.getSaltedHash(newPwd));
        saveUserFile();
    }

    private void saveUserFile() throws Exception {

        users.reformatXML();
        users.writeToFile(userFile);
        timestampLastRead = userFile.lastModified();
        userList.clear();
        userList.addAll(users.getChildren("user", StoredUser.class));
    }

    public void changePassword(String userId, String oldPwd, String newPwd) throws Exception {
        StoredUser foundUser = searchUsersByAny(userId);
        if (foundUser == null) {
            throw new SimpleException("Internal consistency error: unable to find user record for: %s", userId);
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
        StoredUser foundUser = searchUsersByAny(userId);
        if (foundUser == null) {
            throw new SimpleException("Internal consistency error: unable to find user record for: %s", userId);
        }
        String oldName = foundUser.getFullName();
        if (!oldName.equals(newName)) {
            foundUser.setFullName(newName);
            saveUserFile();
        }
    }


    public void updateUserInfo(UserInformation userInfo, String newPwd) throws Exception {
        StoredUser userRec = searchUsersByAny(userInfo.userId);
        if (userRec == null) {
            if (userInfo.alreadyInFile) {
                throw new Exception("Don't understand attempt to update a profile that does not exist.  "
                        +"Clear the 'alreadyInFile' flag to false when you want to create a new profile.");
            }
            //now actually create the user
            userRec = users.addChild("user", StoredUser.class);
            userRec.setKey(userInfo.uniqueKey);
        }
        else if (!userInfo.alreadyInFile) {
            throw new SimpleException(
                    "Don't understand attempt to create a new profile when one with id=%s already exists.  Set the exist flag to update existing profile.", userInfo.userId);
        }
        userRec.setFullName(userInfo.fullName);
        if (userInfo.emailAddress!=null) {
            stripEmailFromAllOtherUsers(userInfo);
            userRec.setEmail(userInfo.emailAddress);
        }
        if (newPwd != null) {
            userRec.setPassword(PasswordEncrypter.getSaltedHash(newPwd));
        }
        saveUserFile();
    }

    private StoredUser searchUsersByAny(String userNetId) {

        for (StoredUser oneUser : userList) {
            if (userNetId.equalsIgnoreCase(oneUser.getEmail())) {
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
        for (StoredUser oneUser : userList) {
            if (userInfo.uniqueKey.equals(oneUser.getKey())) {
                //skip the currently interesting user
                continue;
            }
            oneUser.removeAddress(userInfo.emailAddress);
        }
    }

}
