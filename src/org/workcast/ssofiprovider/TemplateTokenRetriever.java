/*
 * OpenIDServlet.java
 */
package org.workcast.ssofiprovider;

import java.io.Writer;

/**
 * If you wish to use the TemplateStreamer, you have to supply a
 * TemplateTokenRetriever which returns values for the specific tokens.
 * Implement a class that implements this interface, and pass an instance into
 * the TemplateStreamer.
 *
 * There is only one method to implement, writeTokenValue()
 *
 */
public interface TemplateTokenRetriever {

    /**
     * The token passed will be all text between the double curly brace
     * delimiter. This method must determine what associated value is, and write
     * it out.
     *
     * The token can be as complicated an expressions as you want, but it can
     * not have any curly brace characters in it anywhere. You might have a
     * token with multiple parameters as long as you parse out the parameters
     * and recognize their values. If your implementation recognizes the token,
     * then write the value, properly encoded, to the output stream.
     *
     * If the template is HTML, then remember to encode the value using HTML
     * encoding, perhaps by using the TemplateStreamer.writeHtml() function. If
     * you are not sure that the value needs encoding, then encode anyway,
     * because it will eliminate many forms of hacking attacks.
     *
     * Note: throwing an exception from this will cause the streaming of the
     * rest of the template to stop.
     */
    public void writeTokenValue(Writer out, String token) throws Exception;

}
