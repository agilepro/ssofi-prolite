package com.purplehillsbooks.ssofi;

import com.purplehillsbooks.json.JSONException;

/**
 * Parses the address to determine the OpenId and/or the resource
 *
 * is driven by a pattern of one of these two forms:
 *
 * (1) subdomain type: http://{id}.example.com/xx (2) folder type:
 * http://example.com/xx/{id}
 *
 * There is a root address that displays introduction information Root for both
 * above: http://example.com/xx
 *
 *
 */
public class AddressParser {

    // The OpenID is constructed in this way:
    // {valueBeforeId}{id}
    //
    // User must specify a baseURL which is always the beginning of an OpenId
    // followed by the user id.
    // {baseURL}{userid}
    //
    // Entire pattern MUST be all lowercase.
    private static String valueBeforeId;

    // this is the address for future reference
    private String userId;

    // root page is the page where there is no id, the root of the servlet
    private boolean isRootAddr = false;

    public static void initialize(String baseURL) throws Exception {
        valueBeforeId = baseURL;
    }

    /**
     * There are two major patterns, id early and id late here is an example of
     * id early:
     *
     * http://{id}.example.com/
     *
     * In this case there is always a clear before text and after text. The root
     * case is http://example.com/ An example id is http://jsmith.example.com/
     * in this case there must always be a slash on the end (because machine
     * name must have following slash) Here is a resource:
     * http://example.com/$/color.gif The resource path is:
     * http://example.com/$/
     *
     * The second case is late id, and here is an example:
     *
     * http://example.com/{id}
     *
     * In this case, there might be nothing after the id The root case is
     * http://example.com/ An example id is http://example.com/jsmith There is
     * no slash on the end Here is a resource: http://example.com/$/color.gif
     * The resource path is: http://example.com/$/
     *
     * There is a special asset path that must be recognized first, before it
     * attempts to identify an address. This can be configurable.
     */

    public AddressParser(String address) throws Exception {
        if (valueBeforeId == null) {
            throw new RuntimeException("Address Parser class has not been initialized properly, "
                    + "valueBeforeId must be set to appropriate values before "
                    + "creating any instances of the class");
        }

        // normalize to all lowercase, giving case insensitivity
        String addr = address.toLowerCase();

        if (!addr.startsWith(valueBeforeId)) {
            throw new JSONException(
                    "Address Parser only works with requested ID, and that ID must start with ({0}), got this instead: {1}",
                    valueBeforeId, addr);
        }

        userId = addr.substring(valueBeforeId.length());

        // if this is exactly the root page, then return null string
        if (userId.length() == 0) {
            isRootAddr = true;
        }

    }

    public boolean isRoot() {
        return isRootAddr;
    }

    public String getUserId() {
        return userId;
    }

    public String getOpenId() throws Exception {
        return valueBeforeId + userId;
    }

    public static String composeOpenId(String newUser) throws Exception {
        return valueBeforeId + newUser;
    }
}
