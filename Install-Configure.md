# Installing SSOFI Provider

## Data Folder Location

You install the ssofi.war like any normal WAR file into a TomCat.  All information is held in one folder.  The default location is `/opt/SSOFI_Sessions`.  If you are OK with that location then there is nothing you need to change.  If you want to change the location, look into `WEB-INF/config.properties` which holds this one setting for the data file location.  The `config.prperties` file looks like this:

```
# CONFIGURATION FOR SSOFI Identity Provider
#
# This file in the WEB-INF folder tells how to find the data folder
# where all the other configuration settings are.

dataFolder=/opt/SSOFI_Sessions
```

In that folder you will find files like these:

* config.txt - a configuration file holding all the settings
* EmailNotification.properties - a config file with settings to access the SMTP server
* users.xml - the file holding all the user profiles, usually about ~500 bytes per user
* EmailTokens.json - a small file that records tokens while email confirmation is pursued
* XXXXXXXXX.session - a file for each active session for logged in users, ~500 bytes each
* blockedIp.txt - to prevent denial of service attacks, a list of IP addresses that have made too many requests too quickly.

# General Configuration

All of these are found in the /opt/SSOFI_Sessions/config.txt. This location is the default location for the file, but if you placed the data folder in a different location, look for the file there.  Here are all the default settings:

```
# CONFIGURATION FOR SSOFI Identity Provider
#
# You must pick an auth style from the following two:
# authStyle=local
#    this is for email based authentication where users specify a password
# authStyle=ldap
#    this is for authenticating against an LDAP server
authStyle=local

#The baseURL is the address of the server FROM THE USER perspective
#If you are working through a firewall or reverse proxy which change the
#address, then set here the EXTERNAL view of that address.
#Include slash on end.
baseURL=http://kswenson4-t902.corp.fc.local:8080/ssofi2

#set rootURL to the URL base address of the application as seen on this 
#actual server. This setting is necessary to recognize OpenID values 
#when you have a proxy configured to rewrite URL addresses. 
#If you don't have a proxy then this will be the same as baseURL.
#Include slash on end.
rootURL=http://kswenson4-t902.corp.fc.local:8080/ssofi2/

#if sessionFolder is set, then the session information will be stored
#in files in that folder.  For cluster, set this folder to be a shared drive
#sessionFolder=/opt/SSOFI_Sessions

#Set the logged in session duration.  This sets the duration of the cookie
#sent to the browser in seconds.  2500000 is about 1 month.
sessionDurationSeconds=2500000

//Captcha
captchaPublicKey=
captchaPrivateKey=


#the next 10 settings are for LDAP usage
java.naming.factory.initial=com.sun.jndi.ldap.LdapCtxFactory
java.naming.provider.url=ldap\://domain.example.com\:389
java.naming.security.authentication=simple
java.naming.security.principal=domain\\user
java.naming.security.credentials=********
queryBase=DC\=domain,DC\=example,DC\=com
attr.name.uid=username
attr.name.firstName=givenName
attr.name.lastName=lastName
attr.name.mail=mail


```

## authStyle

If you are configuring users in a directory server that provides LDAP access, you can configure SSOFI to read user information from that directory server.  See the rest of the settings below for LDAP.   Otherwise, just leave it as `local` and SSOFI will manage all the information independently.

* authStyle=local - this is for email based authentication where users specify a password
* authStyle=ldap - this is for authenticating against an LDAP server

## baseURL

You must configure the `baseURL` is the address of the server FROM THE USER perspective. If you are working through a firewall or reverse proxy which change the address, then set here the EXTERNAL view of that address. Include slash on end.

## rootURL

Set the `rootURL` to the URL base address of the application as seen on this actual server. This setting is necessary to recognize OpenID values when you have a proxy configured to rewrite URL addresses. If you don't have a proxy then this will be the same as `baseURL`. Include slash on end.

## sessionFolder

if sessionFolder is set, then the session information will be stored in files in that folder. For cluster, set this folder to be a shared drive This is an optional setting.

## sessionDurationSeconds

Set the logged in session duration with sessionDurationSeconds. This sets the duration of the cookie sent to the browser in seconds. 2500000 is about 1 month. If you use this value, users of a particular browser on a particular computer who do not log out, will enjoy automatic continuous access to the authenticated applications, and they will be forced to log in at least once every month.

## Captcha

On public facing hosts use a Captcha to avoid a lot of robot manipulation. `captchaPublicKey` & `captchaPrivateKey`.

# Configuring SSOFI for LDAP

These 10 settings are for LDAP usage

```
java.naming.factory.initial=com.sun.jndi.ldap.LdapCtxFactory
java.naming.provider.url=ldap\://example.com\:389
java.naming.security.authentication=simple
java.naming.security.principal=domain\\user
java.naming.security.credentials=******
queryBase=DC\=domain,DC\=example,DC\=com
attr.name.uid=sAMAccountName
attr.name.firstName=givenName
attr.name.lastName=sn
attr.name.mail=mail
```

## java.naming.factory.initial

The only known value for this is com.sun.jndi.ldap.LdapCtxFactory

## java.naming.provider.url

This is the LDAP url to use to specify the host and the port that the directory server is running on.

## java.naming.security.authentication

Different versions of the LDAP support different types of authentication. The LDAP v2 defines three types of authentication: anonymous, simple (clear-text password), and Kerberos v4.  The LDAP v3 supports anonymous, simple, and SASL authentication. SASL is the Simple Authentication and Security Layer (RFC 2222). It specifies a challenge-response protocol in which data is exchanged between the client and the server for the purposes of authentication and establishment of a security layer on which to carry out subsequent communication. By using SASL, the LDAP can support any type of authentication agreed upon by the LDAP client and server. 

For SSOFI the only viable mode is 'simple' where a username and password are passed to the directory server for authenticating.  

## java.naming.security.principal

Specifies the name of the user/program doing the authentication and depends on the value of the java.naming.security.authentication property.  This is the userid that SSOFI will use to access the server, and so a user must be specified here that has access to the users who are to be authenticated.

## java.naming.security.credentials

Specify the password for the user in java.naming.security.principal

## queryBase

When searching for users, it will search from this point through all the subtree below this point.  Use this to limite the scope of the search to relevant users.

## attr.name.uid

Specify the field to use for the user id.  This is normally 'uid' but it can be other things depending uponn the way the directory server was configured.

## attr.name.firstName

Specify the field that holds the first name, or given name, for the person.  Usually the X.500 standard 'givenName'

## attr.name.lastName

Specify the field that holds the surname for the person.  Usually the X.500 standard 'sn'

## attr.name.mail

Specify the field that holds the email address of the person.  Usually the X.500 standard 'mail'
