<!-- A curated list of every possible vulnerabilities in computer security. -->

<h1 align="center">
  Vulnerabilities
</h1>

<p align="center">
  <a href="https://github.com/askbuddie/vulnerabilities/stargazers" target="_blank"><img alt="GitHub Stars" src="https://img.shields.io/github/stars/askbuddie/vulnerabilities?style=for-the-badge" /></a>
  &nbsp;&nbsp;&nbsp;
  <a href="https://github.com/askbuddie/vulnerabilities/network/members" target="_blank"><img alt="GitHub Forks" src="https://img.shields.io/github/forks/askbuddie/vulnerabilities?style=for-the-badge" /></a>
  <br />
  <strong>A curated list of every possible vulnerabilities in computer security.</strong>
</p>


### Contents

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
  - [Server-Side Template Injection](#server-side-template-injection)
  - [DNS Zone Transfer (AXFR Vulnerability)](#dns-zone-transfer-axfr-vulnerability)
  - [HTTP Request Smuggling](#http-request-smuggling)
  - [RPO Attack](#rpo-attack)
  - [XML Injection](#xml-injection)
  - [Race Condition](#race-condition)
  - [Web Cache Deception](#web-cache-deception)

- [Mobile Application Security Vulnerabilities](#mobile-application-security-vulnerabilities)
  - [Weak Server Side Controls](#weak-server-side-controls)
  - [Lack of Binary Protections](#lack-of-binary-protections)
  - [Insecure Data Storage](#insecure-data-storage)
  - [Unintended Data Leakage](#unintended-data-leakage)
  - [Poor Authorization and Authentication](#poor-authorization-and-authentication)
 
***

## Web Application Security Vulnerabilities

### Cross-site Scripting (XSS): Reflected, Persistent and DOM-based XSS

A type of computer security vulnerability typically found in web applications. XSS enables attackers to inject client-side
scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass
access controls such as the same-origin policy.

---

### SQL Injection (SQLi)

SQL (Structured Query Language) injection is a vulnerability where an attacker can perform malicious query directly to the database
resulting in compromise of whole system. It normally happens when an application accepts user input and takes that to query directly
without any sort of sanitization and hence the databse takes it as a legitimate query and performs the task as per user input. An easy remediation for this is to use prepared statements or completely escape the user inputs.

---

### Cross-site Request Forgery (CSRF)

While performing any changes in an account in an application, it always needs a CSRF token in order to validate the request and know that it is performed by the legitimate user themselves. But when that validation does not work or is improperly configured then
an attacker can create a similar looking form to send the request and let victim unknowingly send the request which leads in changes
in the account of the victim. It is more like : Malicious form --> victim submits it unknowingly --> Unwanted action on victim side takes place.

---

### Server Side Request Forgery (SSRF)

It is a type of vulnerability where an attacker can request the internal resources which are mostly behind the NAT and firewall and aren't accessbile remotely. It is also a result of unsanitized user input directly being used in the code. An attacker can call the response for /etc/passwd, /etc/shadow, files which are unix password files alongside the resources in the localhost.

---

### Remote File Inclusion (RFI)

Remote File Inclusion. Remote File Include (RFI) is an attack technique used to exploit "dynamic file include" mechanisms in web applications.
When web applications take user input (URL, parameter value, etc.) and pass them into file include commands, the web application might be tricked
into including remote files with malicious code.

---

### Local File Inclusion (LFI)

Local File Inclusion (LFI) allows an attacker to include files on a server through the web browser. This vulnerability exists when a web application includes a file without correctly sanitising the input, allowing and attacker to manipulate the input and inject path traversal characters and include other files from the web server.

---

### Remote Code Execution (RCE)

Remote code execution can be best described as an action which involves an attacker executing code remotely using system vulnerabilities. Such code can run
from a remote server, which means that the attack can originate from anywhere around the world giving the attacker access to the PC.

---

### CRLF Injection

A CRLF injection attack is one of several types of injection attacks.It can be used to escalate to more malicious attacks such as Cross-site Scripting (XSS),
page injection, web cache poisoning, cache-based defacement, and more.

---

### LDAP Injection

LDAP Injection is an attack used to exploit web based applications that construct LDAP statements based on user input. When an application fails to properly sanitize user input, it's possible to modify LDAP statements using a local proxy.

---

### Failure to restrict URL Access

Web applications check URL access rights before rendering protected links and buttons. Applications need to perform similar access control checks each time these pages are accessed.
In most of the applications, the privileged pages, locations and resources are not presented to the privileged users.
By an intelligent guess, an attacker can access privilege pages. An attacker can access sensitive pages, invoke functions and view confidential information.
Making use of this vulnerability, attacker can gain access to the unauthorized URLs, without logging into the application and exploit the vulnerability.
An attacker can access sensitive pages, invoke functions and view confidential information.

---

### Insufficient Transport Layer Protection

Deals with information exchange between the user (client) and the server (application).
Applications frequently transmit sensitive information like authentication details, credit card information, and session tokens over a network.
By using weak algorithms or using expired or invalid certificates or not using SSL can allow the communication to be exposed to untrusted users, which may compromise a web application and or steal sensitive information.
Making use of this web security vulnerability, an attacker can sniff legitimate user's credentials and gaining access to the application.
Can steal credit card information.

---

### Unvalidated Redirects and Forwards

The web application uses few methods to redirect and forward users to other pages for an intended purpose.
If there is no proper validation while redirecting to other pages, attackers can make use of this and can redirect victims to phishing or malware sites, or use forwards to access unauthorized pages.
An attacker can send a URL to the user that contains a genuine URL appended with encoded malicious URL.
A user by just seeing the genuine part of the attacker sent URL can browse it and may become a victim.

---

### Insecure Cryptographic Storage

Insecure Cryptographic storage is a common vulnerability which exists when the sensitive data is not stored securely.
The user credentials, profile information, health details, credit card information, etc. come under sensitive data information on a website.
This data will be stored on the application database. When this data are stored improperly by not using encryption or hashing\*, it will be vulnerable to the attackers.
By using this vulnerability, an attacker can steal, modify such weakly protected data to conduct identity theft, credit card fraud or other crimes.

---

### Security Misconfiguration

Security Configuration must be defined and deployed for the application, frameworks, application server, web server, database server, and platform.
If these are properly configured, an attacker can have unauthorized access to sensitive data or functionality.
Making use of this vulnerability, the attacker can enumerate the underlying technology and application server version information,
database information and gain information about the application to mount few more attacks.

---

### Insecure Direct Object References

It occurs when a developer exposes a reference to an internal implementation object, such as a file, directory, or database key as in URL or as a FORM parameter.
The attacker can use this information to access other objects and can create a future attack to access the unauthorized data.
Using this vulnerability, an attacker can gain access to unauthorized internal objects,
can modify data or compromise the application.

---

### Server-Side Template Injection

Template engines are widely used by web applications to present dynamic data via web pages and emails. Unsafely embedding user input in templates enables Server-Side Template Injection, a frequently critical vulnerability that is extremely easy to mistake for Cross-Site Scripting (XSS), or miss entirely. Unlike XSS, Template Injection can be used to directly attack web servers' internals and often obtain Remote Code Execution (RCE), turning every vulnerable application into a potential pivot point.

---

### DNS Zone Transfer (AXFR Vulnerability)

AXFR offers no authentication, so any client can ask a DNS server for a copy of the entire zone. This means that unless some kind of protection is introduced, an attacker can get a list of all hosts for a domain,
which gives them a lot of potential attack vectors.

---

### HTTP Request Smuggling

HTTP Request Smuggling is technique for interfering the way a website processes sequences of HTTP requests from front end servers (usually from loadbalancers or reverse proxies) to back end servers. When an attacker manages to send ambigious request to the server utilising this similar architecture resulting in the different interpretation of the same request by front end and back end, then this vulnerability arises. It usually happens on clear text versions of HTTP.

---

### RPO Attack

RPO (Relative Path Overwrite) relative path coverage, as a relatively new type of attack, first proposed by Gareth Heyes in 2014, uses differences between URL resolutions between nginx servers, misconfigured Apache servers, and browsers. , And use the css or js of the relative path included in the file to read css or js across directories, or even parse a page that is not css or js as css or js, triggering further attacks such as xss.

---

### XML Injection

XML Injection is an attack technique used to manipulate or compromise the logic of an XML application or service. The injection of unintended XML content and/or structures into an XML message can alter the intend logic of the application. Further, XML injection can cause the insertion of malicious content into the resulting message/document.

---

### Race Condition

A race condition is a flaw that produces an unexpected result when the timing of actions impact other actions. An example may be seen on a multithreaded application where actions are being performed on the same data. Race conditions, by their very nature, are difficult to test for.

---

### Web Cache Deception

Modern Web Applications uses cache for storing information on client side so that another time insted of loading files from server, it can load from your cache instead, making the site speed faster. Generally, the files which are retireved often by a web application is cached to reduce latency from the server.

However, if an attacker leverages this opportunity to cache the URL endpoints which may contatin sensitive information and thus making the information publicy accessible, the website is vulnerable to Web Cache Deception Attack.

Let's take an example of a website :
`https://www.samplewebsite.com/user-1/home.php`

Here as we see that there are many users and contents of users are stored on a server, the website processes the endpoint dynamically, as it is different for different users. Such type of personalized data is not cached. But most static files such as stylesheets, scripts and text files are cached. So, what if we request a non-existent statis files such as `https://www.samplewebsite.com/user-1/home.php/style.css`.

A **GET** request will be produced by a browser and if the web-app is not configured properly, the server returns the contents of `https://www.samplewebsite.com/user-1/home.php` which shouldn't be available. In this way an attacker can leverage a Web Cache Deception attack which may lead to information disclosure.

***

## Mobile Application Security Vulnerabilities:

### Weak Server Side Controls

Weak Server Side Controls include almost everythig that a mobile appplication can do badly that does not tak place on the phone, that is it takes place on the server side. The problem in case of mobile developers is that mobile developers often do not always take traditional server-side security considerations into account. To add to that, while most of the threats are fairly similar to OSWAP, the abilities of attackers to manage and get control of a mobile device is very different from what it is on the web. Experience suggests that several factors have lead to a proliferation of server-side vulnerabilities. These factors include: rush to market, lack of security knowledge, easy access to frameworks that don’t prioritize security,lower security budgets for mobile applications, assumption that the mobile OS takes full responsibility for security, weakness due to cross-platform development and compilation, etc.

---

### Lack of Binary Protections

A lack of binary protections within a mobile app exposes the application and it’s owner to a large variety of technical and business risks if the underlying application is insecure or exposes sensitive intellectual property. A lack of binary protections results in a mobile app that can be analyzed, reverse-engineered, and modified by an adversary in rapid fashion. However, an application with binary protection can still be reversed by a dedicated adversary and therefore binary protection is not a perfect security solution. At the end of the day, binary protection only slows down a security review.

---

### Insecure Data Storage

Insecure data storage vulnerabilities occur when development teams assume that users or malware will not have access to a mobile device’s filesystem and subsequent sensitive information in data-stores on the device. Filesystems are easily accessible. Organizations should expect a malicious user or malware to inspect sensitive data stores. Usage of poor encryption libraries is to be avoided. Rooting or jailbreaking a mobile device circumvents any encryption protections. When data is not protected properly, specialized tools are all that is needed to view application data.

---

### Unintended Data Leakage

Unintended data leakage occurs when a developer inadvertently places sensitive information or data in a location on the mobile device that is easily accessible by other apps on the device. First, a developer’s code processes sensitive information supplied by the user or the backend. During that processing, a side-effect (that is unknown to the developer) results in that information being placed into an insecure location on the mobile device that other apps on the device may have open access to. Typically, these side-effects originate from the underlying mobile device’s operating system (OS). This will be a very prevalent vulnerability for code produced by a developer that does not have intimate knowledge of how that information can be stored or processed by the underlying OS. It is easy to detect data leakage by inspecting all mobile device locations that are accessible to all apps for the app’s sensitive information.

---

### Poor Authorization and Authentication

Poor or missing authentication schemes allow an adversary to anonymously execute functionality within the mobile app or backend server used by the mobile app. Weaker authentication for mobile apps is fairly prevalent due to a mobile device's input form factor. The form factor highly encourages short passwords that are often purely based on 4-digit PINs. In traditional web apps, users are expected to be online and authenticate in real-time with a backend server. Throughout their session, there is a reasonable expectation that they will have continuous access to the Internet. In mobile apps, users are not expected to be online at all times during their session. Mobile internet connections are much less reliable or predictable than traditional web connections. Hence, mobile apps may have uptime requirements that require offline authentication. This offline requirement can have profound ramifications on things that developers must consider when implementing mobile authentication.


***

## References

* [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/)
* [OWASP Top 10 Web Application Security Risks](https://owasp.org/www-project-top-ten/)
* [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
* [OWASP Top 10 Privacy Risks](https://owasp.org/www-project-top-10-privacy-risks/)
* [OWASP Desktop App Security Top 10](https://owasp.org/www-project-desktop-app-security-top-10/)
* [OWASP Docker Top 10](https://owasp.org/www-project-docker-top-10/)
* [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/)
