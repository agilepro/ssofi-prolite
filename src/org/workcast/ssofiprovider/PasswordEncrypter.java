package org.workcast.ssofiprovider;

import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * This passord encrypter class does the job of both salting the password and
 * encrypting it, taking the password in as a string, and returning the storage
 * value containing both random salt and encrypted hash as a single string. It
 * then does the job of confirming the password as well, taking both the
 * password and the combined storage value and returning a yes or no.
 *
 * All the methods are static so there is no need to make an instance. Uses
 * standard Java security libraries.
 */
public class PasswordEncrypter {
    // The higher the number of iterations the more
    // expensive computing the hash is for us
    // and also for a brute force attack.
    private static final int iterations = 10;
    private static final int saltLen = 32; // bytes
    private static final int desiredKeyLen = 256;

    /**
     * Computes a salted PBKDF2 hash of given plaintext password suitable for
     * storing in a user profile.
     */
    public static String getSaltedHash(String password) throws Exception {
    	//NOTE: this was taking 20 to 40 seconds on Linux
    	//to get the salt value in this way.  This is not that important
    	//For some reason Linux only provides about 1 byte per second.
    	//
        //byte[] salt = SecureRandom.getInstance("SHA1PRNG").generateSeed(saltLen);
    	//
        
    	//re-implemented salt generation to run much faster in all environments.
    	byte[] salt = new byte[saltLen];
        Random rand = new Random(System.currentTimeMillis());
        for (int i=0; i<saltLen; i++) {
        	salt[i] = (byte) rand.nextInt();
        }
        
        // store the salt with the password
        return hexEncode(salt) + "$" + hash(password, salt);
    }

    /**
     * Checks whether given plaintext password corresponds to a stored salted
     * hash of the password.
     */
    public static boolean check(String password, String stored) throws Exception {
        String[] saltAndPass = stored.split("\\$");
        if (saltAndPass.length != 2) {
            return false;
        }
        String hashOfInput = hash(password, hexDecode(saltAndPass[0]));
        return hashOfInput.equals(saltAndPass[1]);
    }

    // using PBKDF2 from Sun, an alternative is https://github.com/wg/scrypt
    // cf. http://www.unlimitednovelty.com/2012/03/dont-use-bcrypt.html
    private static String hash(String password, byte[] salt) throws Exception {
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey key = f.generateSecret(new PBEKeySpec(password.toCharArray(), salt, iterations,
                desiredKeyLen));
        return hexEncode(key.getEncoded());
    }

    /**
     * generates a hex code value using letters A=0 thru P=15 Yes, base 64 would
     * be more compact, 3/4 this size, but storage size of the key is not any
     * issue, so a simpler easier to prove correct approach is taken.
     */
    public static String hexEncode(byte[] byteArray) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < byteArray.length; i++) {
            int getRidOfByteSign = byteArray[i] + 256;
            sb.append((char) (((getRidOfByteSign >> 4) & 0x0F) + 'A'));
            sb.append((char) (((getRidOfByteSign) & 0x0F) + 'A'));
        }
        return sb.toString();
    }

    /**
     * decodes a hex code value using letters A=0 thru P=15 other characters
     * than these will cause spurious results, but no errors.
     */
    public static byte[] hexDecode(String hexDigits) {
        if (hexDigits.length() % 2 != 0) {
            throw new RuntimeException(
                    "Can not decode an odd number of hex digits.  Something must be wrong");
        }
        int count = hexDigits.length() / 2;
        byte[] res = new byte[count];
        for (int i = 0; i < count; i++) {
            char ch1 = hexDigits.charAt(i * 2);
            char ch2 = hexDigits.charAt(i * 2 + 1);
            int v1 = ch1 - 'A';
            int v2 = ch2 - 'A';
            res[i] = (byte) ((v1 * 16) + v2);
        }
        return res;
    }

    public static void testThis() throws Exception {
        Random rand = new Random();
        byte[] initialTest = new byte[] { 0, 1, 2, 3, 4 };
        checkAndComplain(initialTest);
        for (int iteration = 0; iteration < 100; iteration++) {
            byte[] testCase = new byte[20];
            for (int i = 0; i < 20; i++) {
                testCase[i] = (byte) (rand.nextInt(256) - 128);
            }
            checkAndComplain(testCase);
        }
        for (int iteration = 0; iteration < 100; iteration++) {
            StringBuffer rPass = new StringBuffer();
            int last = 5 + (iteration % 10);
            for (int i = 0; i < last; i++) {
                rPass.append((char) (32 + rand.nextInt(96)));
            }
            String password = rPass.toString();
            String store = getSaltedHash(password);
            if (!check(password, store)) {
                throw new Exception("Unable to hash and verify this password: " + password);
            }
        }
    }

    public static void checkAndComplain(byte[] possibleValue) throws Exception {
        String middle = hexEncode(possibleValue);
        byte[] output = hexDecode(middle);
        for (int i = 0; i < possibleValue.length; i++) {
            if (output[i] != possibleValue[i]) {
                throw new Exception("Value did not match at position '" + i + "' with test case "
                        + middle);
            }
        }

    }
}