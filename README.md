# Vulnerabilities
> List of every possible vulnerabilities in computer security.



### Table Of Content
- [Web Vulnerabilities](#web-vulnerabilities)
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
- [Top Mobile Application Security Vulnerabilities:](#top-mobile-application-security-vulnerabilities)
  - [Weak Server Side Controls](#weak-server-side-controls)
  - [Lack of Binary Protections](#lack-of-binary-protections)
  - [Insecure Data Storage](#insecure-data-storage)
  - [Unintended Data Leakage](#unintended-data-leakage)
  - [Poor Authorization and Authentication](#poor-authorization-and-authentication)



## Web Vulnerabilities
- SQL Injections
- Cross Site Scripting (XSS)
- Broken Authentication & Session Management
- Insecure Direct Object References
- Security Misconfiguration
- Cross-Site Request Forgery(CSRF)



## Web Application Security Vulnerabilities


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

----

### Local File Inclusion (LFI)

----

### Remote Code Execution (RCE)

----

### CRLF Injection

----

### LDAP Injection

----

## Top Mobile Application Security Vulnerabilities:

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
