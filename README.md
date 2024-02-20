# ssofi-prolite
This is a SSOFI Identity Server with the Lightweight Protocol (SLAP) enhancement.

SSOFI was created because there was a need for straight forward way to authenticate users in the Java J2EE environment that would allow a user to sign in once, and then gain access to any number of cooperating servers.  A single SSOFI server forms a domain designated by the URL to that server.   The features are:

* **Strong Protection of Passwords.**  
  * Each password entered by a users is salted and encrypted multiple times in a way to make it very expensive for an attacker to brute-force guess the password.
  * Only the SSOFI server ever has access to the user's actual password.  None of the applications ever see or handle that.
* **Flexible System Architecture.**  
  * SSOFI is designed to provide a single convenient consistent authentication in an environment where there are dozens or hundreds of separate applications located on different cloud server.  The user logs in once, and then is consistently and safely authenticated to each of the cooperating applications.
  * The application that is using the SSOFI service has no constraints on where or how it is deployed.  The application at URL2 can use the SSOFI server at URL1 without any required dependency between URL2 and URL1.  The only requirement is that the application be able to access SSOFI at URL1, and that the SSOFI server can access the application at URL2.
  * The SSOFI server can be configured with a HTTPS connection in order to assure the privacy of the users password while the application is not required to have HTTPS if it is not needed for its data privacy.  Even though we gradually move towards a world where all connections are SSL encrypted, there are still many cases (testing, trials, special purpose, small applications) where setting up SSL can be an unacceptable overhead so SSOFI does not require it.
* **SSOFI Lightweight Access Protocol (SLAP)** simplifies usage from a variety of runtime environments
  * Authentication is performed exclusively with JSON formatted packets with no more than 6 data values.
  * All requests are simple REST GET or POST requests
  * Browsers support JSON natively, so a JavaScript library to implement the protocol has been provided and it is only 200 lines of JavaScript code.
* **Very Low Overhead**
  * SSOFI server does not require a database to be set up or configured.  All data is stored in simple JSON files.
  * A SSOFI server requires only TomCat for the Java web runtime environment along with a single file folder to store all the data.
  * SSOFI will also run in a J2EE environment like JBoss if that is more convenient for the client applications
* **Configurable User Interface.** All user interface screens are implemented using HTML files with template tokens in them so that it is easy to reconfigure the layout, look and feel of the interaction to fit that of the client application.
* **Long term Sessions.**  Users can enter credentials once and remain logged in for long periods of time.  By default a login session is one month.  However, the application is free to have much shorter sessions time, like 30 minutes, to allow for clearing out of cached resources.  The application with the short login session performs an invisible authentication with the SSOFI server to authenticate the user reliably whenever needed.
* **Remembering User ID.** The last user id used at a particular browser is retained for long persions (1 year by default) to simplify the process of logging in for the user.  This burden is not placed on client applications.
* **User Onboarging and Maintenance** SSOFI handles common identity functions so that the client applications do not need to.
  * SSOFI simplifies the development of applications because it handles the user sign up.  Users enter an email address, SSOFI verifies the email address, and allows the user to set a password.
  * Users can reset their passwords at any time through the email.
  * Users associate a full name with their identifier (email address).
* **Integration to LDAP Systems.** SSOFI can be configured in two different modes, and the relying applications have no need to be configured differently for the two different situations.
  * SSOFI can be configured completely stand alone.   Users authentication with email addresses and SSOFI manages the passwords safely.
  * SSOFI can also be configured to authenticate through any LDAP server to handle logging in for applications in situations where the users are being managed in a standard directory server.
* **User Invitation Feature.** The application can leverage the SSOFI server to safely invite users to the system.  A REST API on the SSOFI server allows an application to instruct SSOFI to send an email to an email address along with an invitation message explaining what the invitation is for, as well as a URL to return to.  The email is sent with a single-use token embedded so that the invited user can immediately set their password, and access the application without waiting for another email round trip.  The invitation accomplishes the email verification in a single step, simplifying the job of getting users to join the application.

The whole point of SSOFI is to handle all these identity functions in a secure and reliable way, so that the relying applications need not have the burden.  The relying application only needs to know how to interact using the SLAP protocol, and it is provided then with a logged in user.  The application is relieved of having to collect, guard, and store passwords.  The application needs not provide methods for users to sign up or reset their passwords.  The application need not be configured to send email to support password reset.  The application does not need to have SSL configured to keep passwords private since that application never ever sees or touches a user password.

Not only does this greatly simplify the coding of an application, but it also allows the benefit of single sign-on: the user logs in once, and then any number of separate applciations deployed to separate servers can simply and easily ask "who is this user" and get a reliable response.  This greatly simplifies the implementation of micro-services and single function web services which need a reliable identity, but don't want to take on the full job of providing and guarding that identity.

SSOFI was originally started as a full implementation of OpenID, in order to remove the overhead of OpenID from the individual applciations.   Later OpenID fell out of favor -- probably because the protocol itself was arcane and unweildy -- and so SSOFi was shifted in this version to the lighter-weight SLAP protocol.  More background for SSOFI can be found in my blog post [Social Business: Identity and Reputation](https://social-biz.org/2012/05/30/social-business-identity-and-reputation/) and [SSO Much Fun: Identity Update](https://social-biz.org/2012/05/26/sso-much-fun-identity-update/) as well as a much earlier request for OpenID: [Identity Update: Browsers with OpenID?](https://social-biz.org/2009/05/09/identity-update-browsers-with-openid/).

Future direction is to integrate with external OAuth implementations so that users can leverage their Google ID or Facebook user name when logging in.  Doing so will allow the relying applications to leverage these systems of ID through the SLAP protocol without having to change anything.  This is a fairly straightforward change to make, but I have not found sufficient motivation to spend the time on this at the moment.  Would welcome help to make this enhancement if there are others interested in contributing.

# How To Use

SSOFI is a service that handles the task of authentication, that is, **Logging in**.  It will allow a user to log in once, and then use a collection of web applications freely with the same login.  none of the applications ever sees or handles the password, and so the password is safe from possible rogue applications.  At the same time, a large collectoin of application could be combined together and reliably know who the user is.

See the detail page on [Client Usage of SSOFI](ClientUse.md) to understand how to link an application to allow users to authenticate this way.


# How To Build

All of the executable code is in the `ssofiWar` folder.  You need Maven installed, along with a Java Development Kit (JDK, preferably Java 21 or later).  You build everything using:

```
cd ssofiWar
mvn clean package
```

The WAR file is then located in the `target` folder and can be installed into **TomCat** in the normal way.

# How to Install

It is not difficult to install SSOFI.  You only need a current version of **TomCat** installed.  SSOFI is an application in TomCat and it saves everything as files in a designated folder.  See the [Detailed Installation and Configuration Instructions](Install-Configure.md) for details.
