# Vulnerabilities
> List of every possible vulnerabilities in computer security.



### Table Of Content
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
- [Mobile Application Security Vulnerabilities:](#mobile-application-security-vulnerabilities)
  - [Weak Server Side Controls](#weak-server-side-controls)
  - [Lack of Binary Protections](#lack-of-binary-protections)
  - [Insecure Data Storage](#insecure-data-storage)
  - [Unintended Data Leakage](#unintended-data-leakage)
  - [Poor Authorization and Authentication](#poor-authorization-and-authentication)
  - [Brute Force User Enumeration](#brute-force-user-enumeration)
  - [Cryptography Improper Certificate Validation](cryptography-improper-certificate-validation)
  

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
### Brute Force User Enumeration

----
### Cryptography Improper Certificate Validation

----
