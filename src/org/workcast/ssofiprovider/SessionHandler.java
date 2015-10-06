package org.workcast.ssofiprovider;

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

    /**
     * call this to indicate that the session has been accessed, and to set the
     * timestamp to the current time.
     */
    public void markSessionTime(String sessionId) throws Exception;

}
