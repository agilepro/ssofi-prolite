# ssofi-prolite
This is a SSOFI Identity Server with the LightweightProtocol enhancement.

SSOFI was created because there was a need for straight forward way to authenticate users in the Java J2EE environment that would allow a user to sign in once, and then gain access to any number of cooperating servers.  A single SSOFI server forms a domain designated by the URL to that server.   The features are:

* Strong Protection of Passwords.  Each password entered by a users is salted and encrypted multiple times in a way to make it very expensive for an attacker to brute-force guess the password.
* Flexible System Architecture.  
** The application that is using the SSOFI service has no constraints on where or how it is deployed.  The application at URL2 can use the SSOFI server at URL1 without any required dependency between URL2 and URL1.  The only requirement is that the application be able to access SSOFI at URL1, and that the SSOFI server can access the application at URL2.
** The SSOFI server can be configured with a HTTPS connection in order to assure the privacy of the users password while the application is not required to have HTTPS if it is not needed for its data privacy.  Even though we gradually move towards a world where all connections are SSL encrypted, there are still many cases (testing, trials, special purpose, small applications) where setting up SSL can be an unacceptable overhead so SSOFI does not require it.
* SSOFI Lightweight Access Protocol (SLAP) simplifies usage from a variety of runtime environments
** Authentication is performed exclusively with JSON formatted packets with no more than 6 data values.
** All requests are simple REST GET or POST requests
** Browsers support JSON natively, so a JavaScript library to implement the protocol has been provided and it is only 200 lines of JavaScript code.
* Very Low Overhead
** SSOFI server does not require a database to be set up or configured.  All data is stored in simple JSON files.
** A SSOFI server requires only TomCat for the Java web runtime environment along with a single file folder to store all the data.
** SSOFI will also run in a J2EE environment like JBoss if that is more convenient for the client applications

# build
in the "build" folder there is a "How_To_Build.txt" file that explains how to set up your environment to do a build.

# Installing SSOFI Provider

You install the ssofi.war like any normal WAR file into a TomCat or JBoss. There is only one setting you need to think about before, and that is where you want all of the data files to be. The data files consist of:

* config.txt - a configuration file holding all the settings
* EmailNotification.properties - a config file with settings to access the SMTP server
* users.xml - the file holding all the user profiles, usually about ~500 bytes per user
* EmailTokens.json - a small file that records tokens while email confirmation is pursued
* XXXXXXXXX.session - a file for each active session for logged in users, ~500 bytes each
* blockedIp.txt - to prevent denial of service attacks, a list of IP addresses that have made too many requests too quickly.

The location of all these files in in a single configuration file called WEB-INF/config.properties found in the WAR file. The default location is /opt/SSOFI_Sessions. If you are OK with that default location there is nothing you have to change in the WAR file. Just install into TomCat or JBoss. Or you can change this setting in the WAR file to put the data in a different location.

# CONFIGURATION FOR SSOFI Provider

All of these are found in the /opt/SSOFI_Sessions/config.txt. This location is the default location for the file, but if you placed the data folder in a different location, look for the file there.

You must pick an authStyle from the following two:

* authStyle=local - this is for email based authentication where users specify a password
* authStyle=ldap - this is for authenticating against an LDAP server

You must configure the baseURL is the address of the server FROM THE USER perspective. If you are working through a firewall or reverse proxy which change the address, then set here the EXTERNAL view of that address. Include slash on end.

Set the rootURL to the URL base address of the application as seen on this actual server. This setting is necessary to recognize OpenID values when you have a proxy configured to rewrite URL addresses. If you don't have a proxy then this will be the same as baseURL. Include slash on end.

if sessionFolder is set, then the session information will be stored in files in that folder. For cluster, set this folder to be a shared drive This is an optional setting.

Set the logged in session duration with sessionDurationSeconds. This sets the duration of the cookie sent to the browser in seconds. 2500000 is about 1 month. If you use this value, users of a particular browser on a particular computer who do not log out, will enjoy automatic continuous access to the authenticated applications, and they will be forced to log in at least once every month.

On public facing hosts use a Captcha to avoid a lot of robot manipulation. captchaPublicKey & captchaPrivateKey.

These 10 settings are for LDAP usage

* java.naming.factory.initial=com.sun.jndi.ldap.LdapCtxFactory
* java.naming.provider.url=ldap\://example.com\:389
* java.naming.security.authentication=simple
* java.naming.security.principal=domain\\user
* java.naming.security.credentials=******
* queryBase=DC\=domain,DC\=example,DC\=com
* attr.name.uid=sAMAccountName
* attr.name.firstName=givenName
* attr.name.lastName=sn
* attr.name.mail=mail

