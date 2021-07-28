package com.purplehillsbooks.ssofi;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.spec.KeySpec;
import java.util.Vector;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;

/**
 * The following encryption related methods are from iFlow.jar
 * SSOFI uses those methods to encrypt and decrypt values from property files
 * This way, SSOFI won't depend on iFlow.jar during runtime
 */
class TextEncrypter {
    public static final String DESEDE_ENCRYPTION_SCHEME = "DESede";
    private static final String DES_ENCRYPTION_SCHEME = "DES";
    private static final String DEFAULT_ENCRYPTION_KEY = "Need to encrypt IBPM password";
    private static final String UNICODE_FORMAT = "UTF-8";
    
    private KeySpec keySpec;
    private SecretKeyFactory keyFactory;
    private Cipher cipher;
    private Vector<String> listOfKeys = new Vector<String>();

    TextEncrypter(String encryptionScheme) throws Exception {
        this(encryptionScheme, DEFAULT_ENCRYPTION_KEY);
    }

    TextEncrypter(String encryptionScheme, String encryptionKey) throws Exception {
        populateKeys();
        if(encryptionKey == null) {
            throw new Exception("TextEncrypter: The encryption key is null");
        }
        if(encryptionKey.trim().length() < 24) {
            throw new Exception("TextEncrypter: The encryption key is less than 24 characters");
        }
        byte[] keyAsBytes = encryptionKey.getBytes(UNICODE_FORMAT);

        if(encryptionScheme.equals(DESEDE_ENCRYPTION_SCHEME)) {
            keySpec = new DESedeKeySpec(keyAsBytes);
        } else if (encryptionScheme.equals(DES_ENCRYPTION_SCHEME)) {
            keySpec = new DESKeySpec(keyAsBytes);
        } else {
            throw new Exception("TextEncrypter: The encryption scheme is not valid");
        }

        keyFactory = SecretKeyFactory.getInstance(encryptionScheme);
        cipher = Cipher.getInstance(encryptionScheme);
    }
    
    String encrypt(String unencryptedString) throws Exception {
        if (unencryptedString == null || unencryptedString.length() == 0) {
            throw new Exception("TextEncrypter: The unencrypted string is null or empty");
        }
        SecretKey key = keyFactory.generateSecret(keySpec);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cleartext = unencryptedString.getBytes(UNICODE_FORMAT);
        byte[] ciphertext = cipher.doFinal(cleartext);

        BASE64Encoder base64encoder = new BASE64Encoder();
        return base64encoder.encode(ciphertext);
    }

    String decrypt(String encryptedString) throws Exception {
        if(encryptedString == null || encryptedString.trim().length() <= 0) {
            throw new Exception("TextEncrypter: The encrypted string is null or empty");
        }
        SecretKey key = keyFactory.generateSecret(keySpec);
        cipher.init(Cipher.DECRYPT_MODE, key);
        BASE64Decoder base64decoder = new BASE64Decoder();
        byte[] cleartext = base64decoder.decodeBuffer(encryptedString);
        byte[] ciphertext = cipher.doFinal(cleartext);
        return new String(ciphertext, UNICODE_FORMAT);
    }

    private void populateKeys() {
        // AE Keys
        listOfKeys.add("twfserverpassword");
        listOfKeys.add("dbaloginpassword");
        listOfKeys.add("defaultasappassword");

        // EE Keys
        listOfKeys.add("serverpassword");
        listOfKeys.add("oraclepassword");
        listOfKeys.add("iflowdbpassword");

        // Common Keys
        listOfKeys.add("ldapaccessuserpassword");
        listOfKeys.add("swaplinkagepassword");
        listOfKeys.add("smtppassword");
        listOfKeys.add("smsaccesspassword");

        // PPM Password
        listOfKeys.add("password");
    }
    
    private class BASE64Decoder {
        /*
         * It decipher the passed encoded string. And it return the result in a byte
         * array. If the specified character string can not be deciphered Exception
         * is thrown.
         * 
         * @param String Character string to be deciphered @return byte[] Byte array
         * containing the deciphered bytes @exception Exception If failed during the
         * decipherment
         */

        byte[] decodeBuffer(String str) throws IOException {
            byte[] bytes = null;
            try {
                bytes = str.getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                return null;
            }

            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            ByteArrayInputStream bin = new ByteArrayInputStream(bytes);

            byte bb[] = new byte[4];

            int index = 0;
            int bValue;

            while ((bValue = bin.read()) != -1) {
                if (bValue == '\r' || bValue == '\n' || bValue == ' ') {
                    continue;
                }

                bb[index++] = (byte) bValue;

                if (index != 4) {
                    continue;
                }

                byte rr[] = decode3byte(bb, 0, 4);
                bout.write(rr, 0, rr.length);

                index = 0;
            }

            if (index != 0) {
                byte rr[] = decode3byte(bb, 0, index);
                bout.write(rr, 0, rr.length);
            }

            byte[] result = bout.toByteArray();
            // Bug#16740: Closing the OutputStream & InputStream
            try {
                if (bout != null) {
                    bout.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                if (bin != null) {
                    bin.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

            return result;
        }

        /*
         * It converts the passed byte array into byte array of three bytes (24
         * bits). Confirm and operate the length of the byte on the operated side.
         */
        private byte[] decode3byte(byte[] bb, int offset, int max) throws IOException {
            int num = 0x00000000;
            int len = 0;
            for (int i = 0; i < 4; i++) {
                if (offset + i >= max || bb[offset + i] == '=') {
                    if (i < 2) {
                        throw new IOException(
                                "BASE64Decoder: Incomplete BASE64 character");
                    } else {
                        break;
                    }
                }
                num |= (unmap(bb[offset + i]) << 2) << (24 - 6 * i);
                len++;
            }
            if (len < 3) {
                len = 1;
            } else {
                len--;
            }

            byte rr[] = new byte[len];

            for (int i = 0; i < len; i++) {
                rr[i] = (byte) (num >> (24 - 8 * i));
            }
            return rr;
        }

        /*
         * Converts the character of the Base64 form into the numerical value.
         */
        private byte unmap(int cc) throws IOException {
            if (cc >= 'A' && cc <= 'Z') {
                return (byte) (cc - 'A');
            } else if (cc >= 'a' && cc <= 'z') {
                return (byte) (cc - 'a' + 26);
            } else if (cc >= '0' && cc <= '9') {
                return (byte) (cc - '0' + 52);
            } else if (cc == '+') {
                return 62;
            } else if (cc == '/') {
                return 63;
            } else {
                throw new IOException("BASE64Decoder: Illegal character:= "
                        + (char) cc);
            }
        }
    }

    private class BASE64Encoder {
        /*
         * Encodes by byte array. When byte arrays specified for the argument are
         * null or 0 bytes, the character string of the return value becomes empty
         * string.
         * 
         * @param byte[] Byte array to be encoded @return String Encoded Character
         * string
         */
        String encode(byte[] bytes) {
            if (null == bytes || 0 == bytes.length) {
                return "";
            }

            ByteArrayOutputStream bout = new ByteArrayOutputStream(
                    bytes.length * 150 / 100);

            int max = bytes.length;
            for (int i = 0; i < bytes.length; i += 3) {
                bout.write(create3byte(bytes, i, max), 0, 4);
                // add CRLF at each 76 characters
                if (54 == i % 57) {
                    bout.write('\r');
                    bout.write('\n');
                }
            }
            String result = "";
            try {
                result = bout.toString("UTF-8");
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            // Bug#16740: Closing the OutputStream
            try {
                if (bout != null) {
                    bout.close();
                }
            } catch (IOException e) {
               e.printStackTrace();
            }
            return result;
        }

        /*
         * Converts three bytes into four bytes. Base64 delimits the bit array in
         * three bytes by six bits, and creates four arrays of six bits. Here, 0
         * padding every two head bits of six bits for each is done. In addition,
         * the created each byte is converted into the character-code of Base64. "="
         * is supplemented to an insufficient six bit location when the value of
         * offset+2 exceeds max.
         */
        private byte[] create3byte(byte[] bytes, int offset, int max) {
            byte rr[] = new byte[4];
            int num = 0x00000000;
            num |= (bytes[offset + 0] << 16) & 0xFF0000;

            if (offset + 1 < max) {
                num |= (bytes[offset + 1] << 8) & 0xFF00;
            } else {
                num |= 0;
            }

            if (offset + 2 < max) {
                num |= (bytes[offset + 2] << 0) & 0x00FF;
            } else {
                num |= 0;
            }

            rr[0] = map((num >> 18) & 0x3F);
            rr[1] = map((num >> 12) & 0x3F);

            if (offset + 2 < max) {
                rr[2] = map((num >> 6) & 0x3F);
                rr[3] = map((num >> 0) & 0x3F);
            } else if (1 == (max % 3)) {
                rr[2] = (byte) '=';
                rr[3] = (byte) '=';
            } else if (2 == (max % 3)) {
                rr[2] = map((num >> 6) & 0x3F);
                rr[3] = (byte) '=';
            }
            return rr;
        }

        /*
         * It encodes it to the character of the Base64 form. The correspondence of
         * the numerical value and the character is taken, and ASCII code of the
         * character is set. The character string of the Base64 form is as follows.
         */
        private byte map(int code) {
            code = code & 0x3F;
            if (code <= 25) {
                return (byte) (code - 0 + 'A');
            } else if (code <= 51) {
                return (byte) (code - 26 + 'a');
            } else if (code <= 61) {
                return (byte) (code - 52 + '0');
            } else if (code == 62) {
                return (byte) '+';
            } else {
                return (byte) '/';
            }
        }
     }

}
