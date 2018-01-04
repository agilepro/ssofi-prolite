package com.purplehillsbooks.ssofi;

import java.util.Hashtable;

/**
 * This saves the sessions in a hash table in memory
 */
public class SessionHandlerMemory implements SessionHandler {

    Hashtable<String, AuthSession> allSessions = new Hashtable<String, AuthSession>();
    Hashtable<String, Long> allTimes = new Hashtable<String, Long>();

    public SessionHandlerMemory() throws Exception {
        System.out.println("SSOFI: Using the MEMORY session handler");
    }

    public AuthSession getAuthSession(String sessionId) throws Exception {
        // this represents the earliest time value where the entry could still be valid
        long oneHourAgo = System.currentTimeMillis() - 3600000;
        Long thisTime = allTimes.get(sessionId);
        AuthSession thisSession = null;
        if (thisTime != null && thisTime.longValue() > oneHourAgo) {
            thisSession = allSessions.get(sessionId);
        }

        if (thisSession == null) {
            thisSession = new AuthSession();
            saveAuthSession(sessionId, thisSession);
        }

        // return a copy of this to make sure that update is being done properly
        // and so this memory version is a valid test of the file version
        return thisSession.copy();
    }

    public synchronized void saveAuthSession(String sessionId, AuthSession thisSession) throws Exception {
        allSessions.put(sessionId, thisSession);
        allTimes.put(sessionId, new Long(System.currentTimeMillis()));
    }

    public synchronized void deleteAuthSession(String sessionId) throws Exception {
        allSessions.remove(sessionId);
        allTimes.remove(sessionId);
    }

}
