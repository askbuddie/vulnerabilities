# Vulnerabilities
> List of every possible vulnerabilities in computer security.



### Table Of Content
- [Vulnerabilities](#vulnerabilities)
    - [Table Of Content](#table-of-content)
  - [Web Application Security Vulnerabilities](#web-application-security-vulnerabilities)
    - [Cross-site Scripting (XSS): Reflected, Persistent and DOM-based XSS:](#cross-site-scripting-xss-reflected-persistent-and-dom-based-xss)
    - [SQL Injection (SQLi)](#sql-injection-sqli)
    - [Cross-site Request Forgery (CSRF)](#cross-site-request-forgery-csrf)
    - [Server Side Request Forgery (SSRF)](#server-side-request-forgery-ssrf)
    - [Remote File Inclusion (RFI)](#remote-file-inclusion-rfi)
    - [Local File Inclusion (LFI)](#local-file-inclusion-lfi)
    - [Remote Code Execution (RCE)](#remote-code-execution-rce)
    - [CRLF Injection](#crlf-injection)
    - [LDAP Injection](#ldap-injection)
    - [Failure to restrict URL Access](#failure-to-restrict-url-access)
    - [Insufficient Transport Layer Protection](#insufficient-transport-layer-protection)
    - [Unvalidated Redirects and Forwards](#unvalidated-redirects-and-forwards)
    - [Insecure Cryptographic Storage](#insecure-cryptographic-storage)
    - [Security Misconfiguration](#security-misconfiguration)
    - [Insecure Direct Object References](#insecure-direct-object-references)
  - [Mobile Application Security Vulnerabilities:](#mobile-application-security-vulnerabilities)
    - [Weak Server Side Controls](#weak-server-side-controls)
    - [Lack of Binary Protections](#lack-of-binary-protections)
    - [Insecure Data Storage](#insecure-data-storage)
    - [Unintended Data Leakage](#unintended-data-leakage)
    - [Poor Authorization and Authentication](#poor-authorization-and-authentication)




## Web Application Security Vulnerabilities
- SQL Injection
- Cross Site Scripting (XSS)
- Broken Authentication & Session Management
- Insecure Direct Object References
- Security Misconfiguration
- Cross-Site Request Forgery(CSRF)


### Cross-site Scripting (XSS): Reflected, Persistent and DOM-based XSS:

A type of computer security vulnerability typically found in web applications. XSS enables attackers to inject client-side 
scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass 
access controls such as the same-origin policy.

----

### SQL Injection (SQLi)

SQL (Structured Query Language) injection is a vulnerability where an attacker can perform malicious query directly to the database 
resulting in compromise of whole system. It normally happens when an application accepts user input and takes that to query directly 
without any sort of sanitization and hence the databse takes it as a legitimate query and shows response based on it. 

----

### Cross-site Request Forgery (CSRF)

While performing any changes in an account in an application, it always needs a CSRF token in order to validate the request and know that it is performed by the legitimate user themselves. But when that validation does not work or is improperly configured then 
an attacker can create a similar looking form to send the request and let victim unknowingly send the request which leads in changes 
in the account of the victim. It is more like : Malicious form --> victim submits it unknowingly --> Unwanted action on victim side takes place.

----

### Server Side Request Forgery (SSRF)

It is a type of vulnerability where an attacker can request the internal resources which are mostly behind the NAT and firewall and aren't accessbile remotely. It is also a result of unsanitized user input directly being used in the code. An attacker can call the response for /etc/passwd, /etc/shadow, files which are unix password files alongside the resources in the localhost.

----


### Remote File Inclusion (RFI)

  Remote File Inclusion. Remote File Include (RFI) is an attack technique used to exploit "dynamic file include" mechanisms in web applications.
 When web applications take user input (URL, parameter value, etc.) and pass them into file include commands, the web application might be tricked 
 into including remote files with malicious code.

----

### Local File Inclusion (LFI)

Local File Inclusion (LFI) allows an attacker to include files on a server through the web browser. This vulnerability exists when a web application includes a file without correctly sanitising the input, allowing and attacker to manipulate the input and inject path traversal characters and include other files from the web server.

----

### Remote Code Execution (RCE)

Remote code execution can be best described as an action which involves an attacker executing code remotely using system vulnerabilities. Such code can run
 from a remote server, which means that the attack can originate from anywhere around the world giving the attacker access to the PC.

----

### CRLF Injection
A CRLF injection attack is one of several types of injection attacks.It can be used to escalate to more malicious attacks such as Cross-site Scripting (XSS),
page injection, web cache poisoning, cache-based defacement, and more.

----

### LDAP Injection

LDAP Injection is an attack used to exploit web based applications that construct LDAP statements based on user input. When an application fails to properly sanitize user input, it's possible to modify LDAP statements using a local proxy. 

----

### Failure to restrict URL Access
Web applications check URL access rights before rendering protected links and buttons. Applications need to perform similar access control checks each time these pages are accessed.
In most of the applications, the privileged pages, locations and resources are not presented to the privileged users.
By an intelligent guess, an attacker can access privilege pages. An attacker can access sensitive pages, invoke functions and view confidential information.
Making use of this vulnerability, attacker can gain access to the unauthorized URLs, without logging into the application and exploit the vulnerability.
An attacker can access sensitive pages, invoke functions and view confidential information.

----

### Insufficient Transport Layer Protection
Deals with information exchange between the user (client) and the server (application).
Applications frequently transmit sensitive information like authentication details, credit card information, and session tokens over a network.
By using weak algorithms or using expired or invalid certificates or not using SSL can allow the communication to be exposed to untrusted users, which may compromise a web application and or steal sensitive information.
Making use of this web security vulnerability, an attacker can sniff legitimate user's credentials and gaining access to the application.
Can steal credit card information.

----

### Unvalidated Redirects and Forwards
The web application uses few methods to redirect and forward users to other pages for an intended purpose.
If there is no proper validation while redirecting to other pages, attackers can make use of this and can redirect victims to phishing or malware sites, or use forwards to access unauthorized pages.
An attacker can send a URL to the user that contains a genuine URL appended with encoded malicious URL.
A user by just seeing the genuine part of the attacker sent URL can browse it and may become a victim.

----

### Insecure Cryptographic Storage
Insecure Cryptographic storage is a common vulnerability which exists when the sensitive data is not stored securely.
The user credentials, profile information, health details, credit card information, etc. come under sensitive data information on a website.
This data will be stored on the application database. When this data are stored improperly by not using encryption or hashing*, it will be vulnerable to the attackers.
By using this vulnerability, an attacker can steal, modify such weakly protected data to conduct identity theft, credit card fraud or other crimes.

----

### Security Misconfiguration
Security Configuration must be defined and deployed for the application, frameworks, application server, web server, database server, and platform.
If these are properly configured, an attacker can have unauthorized access to sensitive data or functionality.
Making use of this vulnerability, the attacker can enumerate the underlying technology and application server version information,
database information and gain information about the application to mount few more attacks.

----

### Insecure Direct Object References
It occurs when a developer exposes a reference to an internal implementation object, such as a file, directory, or database key as in URL or as a FORM parameter.
The attacker can use this information to access other objects and can create a future attack to access the unauthorized data.
Using this vulnerability, an attacker can gain access to unauthorized internal objects,
can modify data or compromise the application.

## Mobile Application Security Vulnerabilities:

### Weak Server Side Controls

----

### Lack of Binary Protections

----

### Insecure Data Storage

----

### Unintended Data Leakage

----

### Poor Authorization and Authentication

----
