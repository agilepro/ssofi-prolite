package org.workcast.ssofiprovider;

import java.util.Enumeration;
import java.util.Vector;

/**
 * Generates two types of ID
 *
 * (1) generates an alphanumeric id based on timestamp
 *
 * (2) generates a four digit timestamp unique within a set
 *
 */
public class IdGenerator {
    static long lastKey = 0;

    /**
     * Generates a value based on the current time, but checking that it has not
     * given out this value before. If a key has already been given out for the
     * current time, it increments by one. This method works as long as on the
     * average you get less than one ID per second.
     */
    public synchronized static String generateKey() {
        long ctime = System.currentTimeMillis();
        if (ctime <= lastKey) {
            ctime = lastKey + 1;
        }
        lastKey = ctime;

        // now convert timestamp into cryptic alpha string
        StringBuffer res = new StringBuffer(10);
        while (ctime > 0) {
            res.append((char) ('A' + (ctime % 26)));
            ctime = ctime / 26;
        }
        return res.toString();
    }

    /**
     * Get a four digit numeric id which is unique on the page. Pass in a vector
     * containing all the four digit ids in the current context (on a page, or
     * for a user page, whatever) Generated four digit value will be random, and
     * will not be oneof the values in the vector.
     */
    public synchronized static String generateFourDigit(Vector<String> existingIds)
            throws Exception {
        int seed = (int) (System.currentTimeMillis() % 10000);
        int spin = seed;
        String id = fourDigitConvert(seed);
        while (idAlreadyExists(existingIds, id)) {
            seed = (seed + spin) % 10000;
            spin++;
            id = fourDigitConvert(seed);
        }
        existingIds.add(id); // assume it gets used, no harm
        return id;
    }

    private static boolean idAlreadyExists(Vector<String> existingIds, String currentId) {
        if (existingIds == null) {
            return false;
        }
        Enumeration<String> en = existingIds.elements();
        while (en.hasMoreElements()) {
            String anId = en.nextElement();
            if (anId.equals(currentId)) {
                return true;
            }
        }
        return false;
    }

    public static String fourDigitConvert(int id) {
        StringBuffer res = new StringBuffer();
        for (int i = 0; i < 4; i++) {
            res.append((char) ((id % 10) + '0'));
            id = id / 10;
        }
        return res.toString();
    }

}
