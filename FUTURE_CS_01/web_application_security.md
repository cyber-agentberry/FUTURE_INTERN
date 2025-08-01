## Introduction and Overview of Web Application Security  
In today’s digital era, web applications serve as a critical interface between users and businesses. From banking systems to social media platforms, these applications handle sensitive user data, perform financial transactions, and enable communication on a global scale. However, as their importance has grown, so has their vulnerability to cyberattacks. This makes web application security a crucial area of concern for organizations of all sizes.  
  
## What is Web Application Security?  
Web application security is the process of protecting web-based applications from threats and vulnerabilities that could compromise data integrity, confidentiality, or availability. It involves implementing security controls to prevent attackers from exploiting weaknesses such as:  
- SQL Injection (SQLi)  
- Cross-Site Scripting (XSS)  
- Cross-Site Request Forgery (CSRF)  
- Brute Force Attacks  
- Insecure Authentication  
- Improper Session Management  
These vulnerabilities, if left unchecked, can lead to unauthorized access, data breaches, and system compromise.  
  
## Why Is It Important?  
Web applications are constantly exposed to the public internet, making them an easy and attractive target for malicious actors. A successful attack can result in:  
- Theft of sensitive data (usernames, passwords, credit card info)  
- Service disruption or defacement  
- Unauthorized account access  
- Financial loss and reputational damage  
Ensuring web application security is not just a technical necessity—it’s a business-critical requirement.  
  
## Role of DVWA and OWASP ZAP in Learning  
In this task, DVWA (Damn Vulnerable Web Application) was used as a testbed to simulate common vulnerabilities in a controlled environment. OWASP ZAP acted as the interception and scanning tool to analyze HTTP/HTTPS traffic between the browser and the web server. By capturing requests, inspecting headers, and identifying weak points, it became easier to understand how attackers exploit flaws and how defenders can prevent them.  
  
  
## Setting Up OWASP ZAP for HTTP Interception with DVWA  
This section describes how OWASP ZAP (Zed Attack Proxy) was configured to intercept and inspect HTTP traffic between a web browser and the Damn Vulnerable Web Application (DVWA) running on a virtual machine. This setup is essential for learning how web requests and responses can be monitored and manipulated for security testing purposes.  
  
##Execution Process:  
- Step 1: Accessing the DVWA Platform  
The process began by launching the BWAPP virtual machine, which comes preinstalled with DVWA (Damn Vulnerable Web Application). This was done using VMware Fussion. Once the virtual machine booted up, the IP address of the DVWA server was identified via  ifconfig command inside the VM terminal. Next, a browser was opened on the host machine (the main operating system), and the DVWA login page was accessed. After a successful login, the DVWA dashboard became accessible.   
  
- Step 2: Launching OWASP ZAP  
On the host machine, OWASP ZAP was started by opening a terminal and running the command: zaproxy &  
This command launched the ZAP graphical interface in the background. When prompted, the "Start Now" option was selected to begin a new session without.  
Once launched, ZAP presented several important panels:  
•	Sites: Lists domains and pages visited.  
•	History: Logs each HTTP request/response captured.  
•	Request/Response Details: Allows the user to view and analyze the raw content of HTTP messages.  
  
- Step 3: Configuring Firefox to Use ZAP as a Proxy  
To allow ZAP to intercept browser traffic, the browser (Firefox) was configured to send all traffic through ZAP’s proxy.  
Steps followed in Firefox:  
1.	Opened Settings.  
2.	Scrolled down to Network Settings (bottom of the "General" tab).  
3.	Selected Manual proxy configuration.  
4.	Entered the following details:  
o HTTP Proxy: 127.0.0.1 o Port: 8080  
5.	Checked the option: "Use this proxy server for all protocols".  
6.	Clicked OK to save the configuration.  
⚠ Note: ZAP listens by default on 127.0.0.1:8080, meaning it's ready to receive all HTTP traffic routed through this port.  

  
- Step 4: Verifying That Interception Works  
With Firefox now configured to use ZAP as its proxy, the browser was directed again to the DVWA login page:  http://192.168.56.132/dvwa  
Switching back to ZAP, it was confirmed that the interception was working properly:  
•	Requests appeared under the History tab, showing each HTTP interaction.  
•	The Sites panel populated with the DVWA domain and its internal structure (e.g., login page, vulnerabilities, etc.).  
The DVWA Security level was set to low and an active scan was carried out.  
  

## Vulnerability Analysis: Reflected Cross-Site Scripting (XSS)  
Description:  
Reflected Cross-Site Scripting (XSS) is a web application vulnerability that occurs when user-supplied input is immediately echoed in the application’s response without proper validation or encoding. This enables an attacker to inject and execute malicious JavaScript in the context of the victim’s browser, potentially leading to session hijacking, phishing, or redirection to malicious sites.  
Execution Process:  
The payload was injected into the input field (e.g., “Message” or “Name”). o Upon submission, the payload was reflected in the web page’s HTML response without any sanitization or encoding. o The JavaScript alert executed as soon as the page loaded.  
  

## Result:
- Upon execution of the code, there was an ‘Hello’ message.
- This confirms the presence of a Reflected XSS vulnerability.
- The root cause was the application rendering unsanitized user input directly in the page response.  

  	  
## Vulnerability: Stored Cross-Site Scripting (XSS)  Description:  
Stored Cross-Site Scripting (XSS) is a vulnerability that occurs when user input is permanently stored on the server (e.g., in a database, comment log, etc.) and then displayed to users without proper sanitization or output encoding. When other users view the affected page, the malicious script executes in their browser. This makes stored XSS particularly dangerous, as it can affect every user who views the infected content, unlike reflected XSS which requires a crafted link.  
  
## Execution Process:  
1.	Injection Vector:  
o	The payload was submitted in the Message and Name field of the form. o The script was stored in the server and displayed on the webpage every time it was loaded.  
2.	Execution/Trigger:  
o	After submitting the form, the page displayed the stored message along with the injected script. o The JavaScript executed immediately in the browser, triggering an alert() popup.  
  
  
## Result:  
•	Upon viewing the page after the injection: A pop-up box appeared with the message XSS, confirming that the script ran in the browser context.  
•	This indicates that:
- The user input was not encoded or escaped. 
- No server-side validation or sanitization was in place.
- The content was stored and served back directly to all users.  
  
## Recommendations to Prevent  XSS:  
1.	Sanitize Input: Clean user input to remove dangerous characters.  
2.	Encode Output: Always escape data before displaying it in the browser.  
3.	Use Framework Features: Leverage built-in security like auto-escaping in Django, Flask, etc.  
4.	Avoid Inline Scripts: Keep JavaScript separate and avoid eval().  
5.	Enable Content Security Policy (CSP): Restrict script execution with CSP headers.  
6.	Use Trusted Libraries: Implement filters like DOMPurify or OWASP encoders.  
7.	Perform Regular Testing: Use tools like OWASP ZAP to scan for XSS issues.  
  
## Vulnerability: SQL Injection (Classic)  
##  Description:  
SQL Injection (SQLi) is a common web application vulnerability that occurs when an application fails to properly validate user input before passing it to a database. This allows attackers to inject malicious SQL code to manipulate the application's queries and gain unauthorized access to sensitive data.  
## Methodology:  
In the User ID input field, this payload was used:  
‘OR’ 1=1 –   
     
## Impact:  
•	Unauthorized access to all usernames and data.  
•	Potential for database dumping, credential theft, and privilege escalation.  
•	Could lead to complete system compromise if chained with other attacks.  
•	Shows lack of input sanitization or secure query design.  
  
## Result:  
•	The injected SQL alters the query to return all user records from the database.  
•	Instead of retrieving a specific user ID, the system dumps the entire users table.  
•	This happens because ‘OR’ 1=1 is always true, bypassing intended logic.  
•	The query becomes: SELECT first_name, last_name FROM users WHERE user_id = ''OR’ 1=1 --;  
•	This is a logic-based SQL injection that exposes sensitive backend data.  
  
## Recommendation:  
•	Use parameterized queries or prepared statements.  
•	Sanitize and validate all user inputs.  
•	Employ database-level access controls.  
  
## Vulnerability: Blind SQL Injection (Boolean-Based)  
Description:  
Blind SQL Injection occurs when an application processes SQL queries based on user input but does not directly return results or error messages. Instead, attackers infer database behavior by observing differences in the application's response (such as content or timing) to crafted inputs.  
  

  
## Methodology:  
  
1.	Payloads Used:  
1' AND 1=1 –   
          1' AND 1=2 --   
'OR' 1=1 --    
2.	Execution Process:
-  Payloads were injected into the input field expecting a user ID, if the payload returned a result (e.g., 1' AND 1=1 --), it confirmed that the SQL query was valid , but if no result was returned (e.g., 1' AND 1=2 --), it confirmed the query evaluated to false.
- This behavior confirmed a boolean-based blind SQL injection vulnerability.  
 
  
## Result: 
- Application responses varied depending on logical conditions.
- Although no data was directly visible, the backend logic could be manipulated.  
- This allowed the inference of database structure and behavior.
  
## Impact:  
•	Information Disclosure: Attackers can extract sensitive information by exploiting query logic.  
•	Authentication Bypass: If used on login fields, it may lead to unauthorized access.  
•	Database Enumeration: Slowly determine table names, columns, and data values.  

  
## Recommendations:  
1.	Use Parameterized Queries or Prepared Statements: Ensure all user inputs are safely bound to SQL queries using secure coding practices.  
2.	Input Validation & Sanitization: Reject or sanitize unexpected characters, such as single quotes and SQL control keywords.  
3.	Implement Web Application Firewalls (WAF): Block common attack patterns and monitor suspicious inputs.  
4.	Error Handling: Avoid detailed error messages that could leak backend logic or SQL behavior.  
5.	Security Monitoring: Log and monitor for anomalies in SQL query patterns (e.g., frequent logical injections).  
 
  
## Vulnerability: Cross-Site Request Forgery (CSRF)  
Description:  
Cross-Site Request Forgery is a type of attack where a malicious site causes a user’s browser to perform an unwanted action on a different site where the user is authenticated. DVWA (Damn Vulnerable Web Application) was used to simulate this vulnerability.  
  
## Methodology  
1.	Preparation:
- A malicious HTML form containing hidden fields to change the victim's password was created (Attacker)  
-	The form was hosted on a simple Python HTTP server(python3 -m http.server 8000)  
  
 
## 3.	Execution:  
- Victim was authenticated in DVWA in the same browser.
- Victim visited the attacker’s page and clicked the form button.
- Without user interaction or consent, the password on DVWA was changed to hacked.  
   
  	  
## 4.	Result:  
o	Attacker successfully changed the user’s password.  
o	No CSRF token or validation was present to prevent this.  
  
## Recommendation:  
•	Implement anti-CSRF tokens in all sensitive form actions.  
•	Validate session tokens on the server side.  
•	Use SameSite cookie attributes to limit cross-origin requests.  
  
 
## Brute Force Attack (Burp Suite)  
Vulnerability: Weak Authentication – Brute Force Attack Description:  
Brute Force attacks involve systematically attempting multiple usernamepassword combinations to gain unauthorized access. This test demonstrates a successful brute-force attempt against DVWA’s login page using Burp Suite, without relying on custom wordlists.  
Methodology  
The brute-force attack was carried out by following these steps:  
1.	Proxy Configuration: The web browser was configured to use Burp Suite as a proxy, intercepting all HTTP traffic on 127.0.0.1:8080. Burp Suite's Intercept was enabled to capture requests.  
2.	Request Interception: The DVWA login page was accessed, and a test login attempt was made with arbitrary credentials (e.g., username: admin, password: test). This action generated an HTTP POST request containing the login parameters, which was successfully intercepted by Burp Suite.  
3.	Sending to Intruder: The captured POST request was sent to the Burp Suite Intruder tool for automated payload injection.  
4.	Payload Configuration:  
o Positions: The Intruder's "Positions" tab was used to define the attack points. All default payload markers were cleared, and new markers (§...§) were manually placed around the username and password parameters within the POST body.  
§	Attack Type: The "Cluster Bomb" attack type was chosen. This type is designed to iterate through multiple independent payload sets, testing every possible combination of payloads for each defined position. In this case, it tested every username from the first payload set with every password from the second payload set.  
§	Payloads: Instead of an external wordlist, Burp Suite's built-in "Simple List" payload type was utilized for each payload position.  
•	Payload  	Set  	1  	(Username): A  	list  	of  	common  usernames  
(admin, user, guest) was provided.  
•	Payload  	Set  	2  	(Password): A  	list  	of  	common  passwords (password, admin, 123456) was provided.  
•	Configuration: The Intruder was configured to run a total of 3 x 3 = 9 requests, systematically testing each username/password pair.  
5.	Running the Attack: The attack was launched from the Intruder interface. Burp Suite automatically iterated through the payload lists, sending a series of HTTP POST requests to the DVWA server with different username and password combinations.  
6.	Analysis: The results of each request were monitored in the Intruder's "Results" tab. The analysis focused on the HTTP status codes and the response lengths of each request. A successful login attempt typically resulted in a different HTTP status code (e.g., a 302 Found redirect to the user's home page) or a unique response content length compared to failed login attempts. This deviation was a clear indicator of a successful credential guess.  
  
  
## 7.	Findings & Observations  
•	Vulnerability: The DVWA login form is highly susceptible to brute-force attacks due to the lack of effective security measures.  
•	Authentication Flaw: The application does not enforce rate limiting on login attempts. An attacker can submit an unlimited number of login requests in a short period without being blocked.  
•	Credential Guessing: The attack successfully identified a valid username/password combination (admin/password), demonstrating that the use of weak, predictable credentials coupled with the lack of security controls makes the application trivial to compromise.  
•	Response Analysis: Analyzing the HTTP response lengths proved to be a highly effective method for identifying a successful login. The content length for a successful login was significantly different from that of a failed attempt.  
•	Automated Guessing: The exercise successfully proved that an attacker does not need a large, custom wordlist to perform a brute-force attack. Burp Suite's built-in tools and a small, simple list of common credentials were sufficient to compromise the application.  
  
## Recommendations:  
To mitigate the risk of brute-force attacks, the following security measures are strongly recommended:  
•	Implement Rate Limiting: Enforce a limit on the number of login attempts from a single IP address over a specific time period.  
•	Account Lockout Policy: After a predefined number of consecutive failed login attempts (e.g., 3-5), temporarily lock the user account to prevent further attempts.  
•	Use of CAPTCHA: Implement a CAPTCHA or similar challenge- 
response test after a certain number of failed login attempts to distinguish human users from automated bots.  
•	Credential Complexity: Enforce strong password policies that require a minimum length and a mix of characters (uppercase, lowercase, numbers, special characters) to make brute-forcing more difficult.  
•	Multi-Factor Authentication (MFA): Implement MFA as an additional layer of security, requiring users to provide a second form of verification besides their password.  
  
  


 	 
## Conclusion
The vulnerability assessment of the Damn Vulnerable Web Application (DVWA) at a low-security level successfully identified and exploited multiple critical security flaws. The tests conducted, including Cross-Site Scripting (Reflected and Stored), SQL Injection (Classic and Blind), Cross-Site Request Forgery (CSRF), and a Brute Force attack, all demonstrated the application's severe lack of fundamental security controls.  
The findings highlight a direct correlation between weak security implementation and the ease of exploitation. The application's failure to sanitize user input, implement secure query practices, validate session tokens, or enforce rate limiting mechanisms made it trivial to compromise.  
In summary, the DVWA platform, under its low-security configuration, is highly vulnerable to a range of common web application attacks. The successful exploits detailed in this report serve as a practical illustration of why robust security measures—such as input validation, output encoding, prepared statements, CSRF tokens, and brute-force protections—are not just best practices, but essential requirements for any web application handling user data. Addressing these vulnerabilities is critical to preventing unauthorized access, data breaches, and other significant security incidents in a real-world environment.  
  
[Screenshots]()  
