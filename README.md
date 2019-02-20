# ssofi-prolite
This is a SSOFI Identity Server with the LightweightProtocol enhancement

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

