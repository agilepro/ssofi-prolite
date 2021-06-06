package com.purplehillsbooks.ssofi;

/**
 * An interface to represent the various possible authentication options: LDAP,
 * LocalFile, others.
 */
public interface AuthStyle {

    /**
     * Retrieve and return the information about the specified user
     * or return a null if the user does not exist
     */
    public UserInformation getExistingUserOrNull(String idOrKey) throws Exception;


    /**
     * Retrieve and return the information about the specified user
     * UserInformation has a 'exists' flag saying whether a profile exists or
     * not. This method should never return null. Instead, return empty record
     * with exist=false;
     */
    public UserInformation getOrCreateUser(String idOrKey) throws Exception;


    /**
     * Either update or create a user profile for specified user. If the
     * password parameter is non-null, then reset the password to the specified
     * value. Used in password reset/recovery situations.
     */
    public void updateUserInfo(UserInformation user, String newPassword) throws Exception;

    /**
     * Verify that the supplied password is correct for the given user id
     */
    public boolean authenticateUser(String userNetId, String userPwd) throws Exception;

    /**
     * Verify that the supplied old password is correct for the given user id,
     * and if so set it to the supplied new password.
     */
    public void changePassword(String userId, String oldPwd, String newPwd) throws Exception;

    /**
     * Verify that the supplied old password is correct for the given user id,
     * and if so set it to the supplied new password.
     */
    public void changeFullName(String userId, String newName) throws Exception;

    /**
     * Forcefully reset the password for the given user id
     */
    public void setPassword(String userId, String newPwd) throws Exception;

    /**
     * Get a small string that can uniquely identify resources for this auth
     * style a resource might have the name "InputScreen.htm" and
     * "InputScreen.xxx.htm" for the version specialized for the 'xxx' auth
     * style. This method returns the 'xxx' in that case.
     */
    public String getStyleIndicator();

    /**
     * Search for closest ID
     */
    //public String searchForID(String searchTerm) throws Exception;
}
