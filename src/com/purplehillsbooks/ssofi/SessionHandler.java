package com.purplehillsbooks.ssofi;

/**
 * This is the interface that a session handler must implement
 */
public interface SessionHandler {

    /**
     * pass in the session id, and get the session information back
     */
    public AuthSession getAuthSession(String sessionId) throws Exception;

    /**
     * if the session values are changed in any way, use this method to update
     * the persisted session record.
     */
    public void saveAuthSession(String sessionId, AuthSession thisSession) throws Exception;

    /**
     * if the session values are changed in any way, use this method to update
     * the persisted session record.
     */
    public void deleteAuthSession(String sessionId) throws Exception;


}
