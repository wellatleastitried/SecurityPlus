# Security+ Study Guide (Work in progress)
This study guide is something that I threw together while studying for the CompTIA Security+ certification. While there are examples provided for some of the concepts mentioned, this guide is primarily just definitions. I did my best to try and include every topic that is important to know before taking the certification exam. **All of the material used to create this guide is from Professor Messer's Youtube series and the Cybrary Security+ course.**
## Social Engineering
In social engineering, there are many different forms of attacks. These specific types of attacks are a non-technical way of gaining access to resources that would otherwise be unobtainable (often times through impersonation). Social Engineering is responsible for around 90% of all data breaches in corporations. There are many different types of social engineering attacks but the primary ones that are important to be wary of are as follows:
### Phishing Attacks
Phishing is a broad term used to describe **an attacker sending a text or email containing a link that tries to coerce the user into entering personal information for the attacker to steal**. When dealing with possible phishing attacks, it is important to be on the lookout for the following things:
  - Graphics that are slightly "off"
  - Pretexting: An attacker trying to create a situation that will coerce you into clicking the link. ("Your debit card has been charged $500! Click this link to contest the payment.")
  - Use of typo-squatting: An attacker using www[.]google[.]co**n** instead of www[.]google[.]com
  - Email header: Ensure the person that has sent the email is known or from a trusted background.
### Pharming Attacks
Pharming is a social engineering **attack where a legit website is redirected to a bogus site**. This is usually done through either a poisoned DNS server or a vulnerability on the client side. This form of attack is often combined with phishing to harvest credentials from a large group of people. It is very difficult for anti-malware to stop and often appears completely legit to the users.
### Vishing
Vishing, similar to phishing, is a way for an attacker to get credentials from the target by coercing the information out of them. However, unlike phishing, this is done over the phone or voicemail instead of through a text or email. In these attacks, called ID spoofing is extremely common so it can be hard to determine whether the number is real or fake. These calls can be masked as anything, whether it be security checks or even bank updates. One of the most important things to remember about vishing prevention is that you should never give personal information to someone who calls **you**. If you need to give information over the phone, make sure that you are calling **them** or, at the *very* least, double check the caller to try and verify who you are talking to.
### Smishing
Smishing is a subset of phishing that is done over specifically SMS. Similar to vishing, spoofing the number the text is being sent from is extremely common.
### Hoaxes
Hoaxes are situations that are created by the attacker that assist in persuading the intended target to perform an action that they might not otherwise do. These situations can range from the promises of financial gain to the attacker convincing the user to delete or move important files because they are "not safe." Hoaxes are *usually* used to waste time, but they can also be more malicious.
### Identity Fraud
Using information (which is often times obtained through other forms of social engineering attacks) to present yourself to be someone else (usually someone with higher clearance or status).
### Shoulder Surfing
Shoulder surfing is when an attacker watches their target enter personal information into their device for the sole purpose of learning their credentials. This is more common than you may think and can happen anywhere, whether it be coffee shops, airports, banks, or even someone looking with binoculars from a building over. To help mitigate the likelihood of this happening:
  - Pay attention to your surroundings
  - Use privacy screens on your devices to limit how much others can see of your screen
### Dumpster Diving
While this is a tactic for reconnaissance rather than an actual attack, it is still important to mention. Important information can be thrown out in the trash where future attackers can find important details to use in their later attacks. Dumpster diving is often done either at the end of the month or at the end of the quarter and is also done in alignment with the trash pickup schedule. This is completely legal in the United States as a whole, but local laws may have stricter rules to follow. In general, if it is in the trash, no one owns it. The main exception is dumpsters on private property, as laws cannot be broken to get *to* the dumpster. To combat dumpster diving, it is important to **shred documents with sensitive information** and to **keep dumpsters under lock and key and/or fenced off.**
### Spam
Spam is when someone sends unrequested bulk messages in large quantities. The most common example of this is a person sending an email to as many people as possible in order to advertise or push an agenda. While this is not necessarily a form of social engineering, it is often linked with phishing attacks in order to try and maximize the number of possible targets. In addition to this, it can also be used to overwhelm mail servers.
### Spim
Spim is the same concept as spam with the difference of the messages being sent over text.
### Bluejacking
Bluejacking is the term used to define spam that is sent over Bluetooth connections.
### Watering Hole Attack
A watering hole attack is when malware is injecting through an insecure, frequently used third party. If an attacker is unable to gain access to Company A's network, but they know that employees of Company A frequently visit Company B's website, the attacker can inject Company B's website with malware so that the employees of Company A that visit this site get infected.
### Tailgating
Following an authorized user into a secure area without having to provide your own credentials.
### Piggybacking
Having an authorized user let you into a secure area without having the proper credentials.
### Influence Campaigns
Influence campaigns are large scale programs (often launched by a hostile nation) that are geared toward swaying public opinion. A common use-case example would be foreign countries trying to sway election results. Social media is one of the primary targets for these campaigns as it is easy to reach a wide range of people.
### General Notes about Social Engineering
Attackers often spend time gathering info on the specific victim. They will look at social media, corporate sites, etc. to try and build a believable pretext in relation to:
  - Where you work
  - Recent transactions
  - Where you bank
  - Your family and friends\
When a target is specifically chosen for a phishing attack, it is often referred to as **Spear Phishing**. Spear Phishing of a high profile target with higher levels of access (such as a CEO or CFO since these targets would have direct access to the corporate bank account) is referred to as **Whaling**.\
Prepending, in the context of spam and phishing, is when the sender adds information to the message to legitimize it (A common example being adding "Re: " to the subject line to make the email appear as a reply).
## Indicators of Attacks
### Threat Actors
-  State-sponsored Attacks: North Korea, China, Russia
  -  APT (Advanced Persistent Threats)
-  Internal Threats:
  -  80% of all fraud is initiated from within the organization
  -  $2/3$ of security-related incidents from within are unintentional
### Attack Vectors
A means of creating a compromise and accessing a system.
-  Direct access
-  Backdoor software
-  Email
-  Gaining information from source like social media, keyloggers, etc
#### Cyber Kill Chain
1.  Reconnaissance: Attacker researches target network and attempts to identify vulnerabilities
2.  Weaponization: The attacker either adapts an existing remote access malware weapon or creates a new one, tailored to one or more vulnerabilities identified in the previous step
3. Delivery: The attacker transmits the weapon to the target (e.g., via email, attachments, links to malicious websites, or USB drives)
4. Exploitation: The malware weapon triggers, which takes action on the target to exploit one or more vulnerabilities and compromise the host
5. Installation: The malware weapon installs an access point (such as a backdoor) usable by the attacker
6. Command and Control: The malware enables the attacker to have "hands on the keyboard" persistent access to the target network
7. Actions and Objective: The attacker takes actions to achieve their goals, such as data exfiltration, data destruction, or encryption for ransom
### Threat Vectors
  - Viruses: Usually require a host file and user interaction
    - File-less viruses do not need a host
  - Worms: A memory resident type of malware that can self-propagate and does not need a host file
  - Trojans: Present themselves as a desirable application or tool, yet contain malware
  - PUPs/PUAs (Potentially Unwanted Programs/Applications): Software that is installed in addition to the app the user has chosen. Sometimes called gray-ware, as it is not always malicious
  - Other threat classifications can be determined by the payload. (A RAT, a Remote Access Trojan, can be delivered by a Trojan)
### Command Line Tools
TODO
### Attack Frameworks
TODO
### Unauthorized Access
  - Backdoor: Network software that opens a port on the compromised system. The host then "listens" for traffic on that port and allows access to the system, bypassing all of the installed authentication methods
  - RATs: A type of backdoor software that allows covert administrative access to a system
  - Bot: An automated script or tool that performs malicious activity
  - Botnet: A collection of systems controlled by the same threat actor
  - Command and Control (C2 or C&C): Host or network that communicates with the exploited hosts
  - Rootkit: Operates at executive level (root or administrator depending on OS) or can be used to escalate privileges
### Ransomware
Computer-based attack that allows the attacker to extort money from the target. Usually displays a message on the compromised machine telling the target to pay a specified sum of money to fix their compromised machine. These attacks use crypto-malware, which encrypts critical systems or files and requires the user to pay a fee or ransom in exchange for the key to decrypt their data.
### Logic and Time Bombs
**Not all malware runs immediately**
  - Time Bombs wait until a specific date or time to unleash their payload
  - Logic bombs wait until a specified event, such as the tenth time a file is accessed, before delivering the payload
### Spyware
Malware used to track the activity of users
  - Tracking cookies: Plain text files stored on the user's machine that can record pages visited, purchases made, shopping cart contents, search queries, etc., often used in conjunction with adware
  - Adware: Often reconfigures browsers to target market to an individual based on previous activities. May reconfigure browser to load ad-filled home page
  - Keylogger: Records keystrokes on the target machine
### Password Attacks
  - Dictionary: Guesses every word in a specified file
  - Brute Force: Guesses every combination of the specified characters
  - Hybrid: Guesses every word in a file plus some frequently used character combinations
  - Rainbow Table: Stored results from a brute force attack matched against the password hash. **Much** faster than running the brute force attack itself.
  - Spraying: Attempting a common password like "Password123" to numerous accounts
One of the biggest mistakes that can be made when configuring a server is to have plaintext/unencrypted databases or protocols. This can lead to passwords and other critical data being leaked. Having secure passwords is something that can be easily accomplished, but humans are lazy and often opt for the passwords that are easier to remember.
### Physical Security Threats
  - Malicious USB Cables: Can act as a skimmer over legitimate charging stations at public locations such as airports
  - Flash Drives: Can provide the means to distribute malware, as well as to remove sensitive information from the machine they are plugged into
  - Card Cloning: Making mulitple copies of an existing card
  - Skimming: Installing a counterfeit card reader over a legitimate device
### AI Data Poisoning
  - Tainted Traning Data for Machine Learning: AI systems "learn" based on data retrieved from customer systems and security devices like honeypots. By injecting code or traffic into the training environment, an attacker can corrupt the learning process, therefore rendering the AI software skewed.
  - Machine Learning Algorithms: Machine learning algorithms can be targeted the same as others.
### 3<sup>rd</sup> Party Attacks
  - Supply Chain: Compromising elements of a system provided by another party. For example, if the processor is compromised at the vendor, then the system will never be secure. Could also exploit 3<sup>rd</sup> party access to a system or environment.
  - Cloud-based Attacks: Attacks at the CSP itself or protocols/apps/accounts used to access and transmit data to and from CSPs
  - Poorly written APIs are a common target as well
### Cryptographic Attacks
  - Collision Attack: Attempting to create a cryptographic collision to identify another series of characters that will produce the same hash as the legitimate password.
  - Birthday Attacks: Attempts to cause a collision based on the fact that that it is mathematically infeasible to cause a collision with a specific hash, and that it is more likely to find two hashes that just happen to match. Again, mathematically infeasible but more probable.
  - Downgrade Attacks: Requests access to the server at a lower level of security than the default in hopes that passwords would be transmitted in a less secure manner.
### Pass the Hash
Password hashes are stored in protective memory on our systems. There could be numerous hashes stored in the memory, for example, the current user, remote users, or service accounts. If these hashes are accessed by an attacker (who would need root privileges to do so), the attacker may be able to exploit the SSO authentication to use the hashes elsewhere to authenticate. It is important that users should not have debug privileges or be administrators (root) on their local machines.
### Timing Attacks
  - Physical Access: Gain access to a location before security requirements are verified
  - Race Conditions: Technical in nature. Revolve around technical timing exploits
  - TOC/TOU: Time of Check/Time of Use
  - Replay Attacks: Traffic is captured and then used again later
  - Error Handling: Error messages should not give the user *too* much information as it can give the attacker a target
### Memory Issues
  - Integer Overflow: An integer overflow is when a provided value is out of the expected range
  - Buffer Overflow: More entries are provided than expected, resulting in memory that is beyond the size of the buffer being accessed
  - Memory Leak: Application does not release memory in its intended way\
Input validation is *vital* to ensure the memory safety of applications.
### Network-based Attacks
-  Port Scanning
-  Xmas Scans: Sends a packet with all flags set with a combination normal conversation never uses - can be used to determine operating system and open ports
-  Man-in-the-middle: Attacker inserts himself into a communication path
  -  Passive: Sniffing
  -  Active: Session hijacking
- Fuzzing: Attempting to inject code in vulnerable applications. Can be used for software penetration testing also
-  Banner grabbing: Some network services return information in response to a service request
#### Spoofing
-  IP spoofing
-  MAC spoofing/Cloning
-  Email spoofing
-  Caller ID spoofing
-  Smurf attack
-  Fraggle attack
#### Redirection
-  ARP: Address Resolution Protocol
  -  Poisoning
-  DNS
  -  Rogue Infrastructure
  -  Poisoning
  -  Pharming
  -  Hosts file
- URL redirection
#### Wifi Attacks
-  Wardriving/Warchalking
-  Encryption
-  Sniffing:
  -  WEP
  -  WPA
  -  WPA II
-  WPS attacks
-  Rogue Access Points/Evil Twins
-  Dissociation/Deauthentication
-  Jamming
#### Bluetooth
-  Bluejacking
-  Bluesnarfing
-  Bluebugging
## Indicators for Application Attacks
### Code Injection
Input validation and sanitization are vital in applications. Weak handling of inputs can lead to:
  - SQL Injection
  - DLL Injection
  - LDAP Injection
  - XML Injection
  - XSS (Cross-site Scripting) Attacks: Stored, Reflected/Non-persistent, Dom-based
  - XSRF (Cross-site Request Forgery)
  - Timing Attacks
  - Buffer/Integer Overflows
  - Memory Leaks
### Cross-Site Attacks
Steps with example scenarios:
#### Cross-Site Scripting (XSS)
Takes advantage of a user's trust in a website.
###### Steps of Persistent XSS Attack:
  - Adversary finds a site vulnerable to script injection
  - Adversary injects site with malicious script that steals user's session cookies
  - User activates malicious script each time they access the site
  - User's session cookie is sent to the adversary
###### Steps of Reflective XSS Attack (Non-Persistent):
1. Adversary sends URL with malicious string to user
2. User tricked into opening link and requesting malicious URL from site
3. Site includes malicious string in its response to user
4. User's browser interprets malicious script as part of the legitimate webpage and executes the code
#### Cross-Site Request Forgery (XSRF)
Takes advantage of a website's trust in a user.
###### Steps of XSRF:
1. Adversary forges a request for a fund transfer to a site
2. Adversary embeds request in a link and sends it to users who may be logged in to site
3. User clicks link, unintentionally sending request to site
4. Site validates request and transfers funds from the visitor's account to the adversary
## Security Assessments
### Vulnerability Management Activities
- A common way to identify technical vulnerabilities use a vulnerability scanner
  - Nikto
  - Nessus
  - Critical components of a vulnerability scanner:
    - Credentials: can scan with or without user credentials
      - Uncredentialled scan: non-credentialed scans, do not get trusted access to the systems they are scanning
      - Credentialed scan: require logging in and provide access to resources an untrusted user would not have
    - Agent/Agentless: can be run without an agent or be configured to run with agents installed on the local devices
    - Intrusive/Non-intrusive: Non-intrusive scans identify a vulnerability and report on it. Intrusive scans attempt to exploit a vulnerability
- Patch management is a way to manage software vulnerabilities
  - Identify missing updates or patches for the devices on your network
    - **Not just for operating systems:** devices such as firewalls and switches have firmware updates
  - Install missing patches to keep systems fully up-to-date and secure
- Performing a risk assessment will help you to find areas that perhaps you didn't consider as being vulnerable
- Vulnerability Information Sources:
  - Advisories: specific data on an identified vulnerability
  - Bulletins: summaries/newsletter listings of advisories
  - Information Sharing and Analysis Centers (ISACs): non-profit groups that specialize in a specific sector
  - News Reports: news articles or headlines
- Security Content Automation Protocol (SCAP): A suite of interoperable specs designed to standardize the naming conventions and formatting used to identify and report on software flaws. Made up of open standards to enumerate software flaws and security related configuration issues.
  - Languages Include:
    - Open Vulnerability and Assessment Language (OVAL): Provides a way to collect and assess three main aspects of evaluated systems: system information, machine state, reporting
    - Asset Reporting Format (ARF): correlates reporting formats to device information
    - Extensible Configuration Checklist Description Format (XCCDF): Written in XML to provide a consistent way to define benchmarks and checks performed during assessments
  - Identification Schemes:
    - Common Platform Enumeration (CPE): standardized naming format to identify systems and software
    - Common Vulnerabilities and Exposures (CVE): lists of known vulnerabilities. Format is CVE-YEAR-XXXX
    - Common Configuration Enumeration (CCE): Similar to CVE but focuses on configuration issues that may lead to a vulnerability
- Honeypots:
  - Deployment:
    - Pseudo Flaw: Loophole purposely added to operating system or application to trap intruders
    - Sacrificial lamb system on the network
    - Administrators hope that intruders will attack this system instead of their production systems
    - It is enticing because many ports are open and services are running
  - Be careful of Enticement vs Entrapment
- Log Reviews
  - Examination of system log files to detect security events or to verify the effectiveness of security controls
  - Ensure that time is standardized across all networked devices
- Syslog:
  - A standard network-based logging protocol that works on a wide variety of different types of devices and applications, allowing them to send text-formatted log messages to a central server
- Security Information and Event Managers:
  - Systems that enable the centralization, correlation, and retention of event data in order to generate automated alerts
  - Also useful for forecasting and trend analysis
## Threat Intelligence
- Strategic Intelligence is non-technical, high-level information that can be used by senior management to make security decisions
- Operational intelligence focuses on adversaries and their actions
- Tactical intelligence focuses on immediate, specific threats and the evidence which can be used to detect them
- Counterintelligence is an active security strategy that uses intelligence offensively
- Intelligence source types:
  - Open-source intelligence (OSINT)
  - Closed-source intelligence/proprietary intelligence
- Threat intelligence organizations:
  - Computer Emergency Response Teams (CERT)
  - Information Sharing and Analysis Center (ISAC)
  - MITRE
- Threat awareness:
  - Known threats:
    - Long-established threats can still be potent against weak security or if a new attack variant emerges
  - Current vulnerabilities:
    - Documented vulnerabilities in hardware, software, or procedures are continually changing, so you must remain aware of them
  - Trending attacks:
    - Attackers frequently adopt new strategies as defenses and vulnerabilities change
  - Emerging threat sources
  - Ongoing changes in technologies and business practices can affect both individual attacks and the security landscape
  - Zero-day vulnerabilities
  - Newly discovered vulnerabilities are an especially dangerous threat
- Intelligence gathering:
  - Define intelligence requirements - the goals and priorities for intelligence gathering
  - Collect and process information that is likely to meet your requirements
  - Analyze processed information to turn it into actionable intelligence
  - Disseminate intelligence to the decision-makers who can act on it according to organizational policies
  - Generate feedback to improve the next round of the cycle
- Threat hunting:
  - Threat hunting uses threat intelligence to develop hypotheses and analytics based on what threat actors are known to do so that threats can be proactively found rather than passively detected
  - Advisories and bulletins: information released by vendors and researchers about new TTPs (Tactics, Techniques, and Procedures) and vulnerability information
- Cybersecurity information sources:
  - Social media
  - Vendor websites
  - Academic journals
  - Conferences
  - Threat actor activities
  - Request for comments (RFC)
- Threat Intelligence sources:
  - Data repositories
  - Vulnerability feeds
  - Threat intelligence feeds
  - Threat maps
  - Predictive analysis
- Threat indicators:
  - Reputational indicator: An indicator of attack (IoA) that is associated with a known or likely threat source
  - Behavioral indicator: An IoA associated with a known suspected action performed by attackers
  - Indicators of Compromise: A piece of forensic data which is associated with malicious activity on a system or network
  - Vulnerability: A weakness in a system or network which can be exploited by a threat actor
## Penetration Testing
Active, potentially intrusive process of simulating attacks on a network
- Penetration testing uses a set of procedures and tools designed to test and possible bypass the security controls of a system
- Goal is to measure an organization's level of resistance to an attack and to uncover any weaknesses within the environment
- Emulates the same methods attackers would use
- Penetration testing should only be conducted with senior management's approval in writing (it's only ethical hacking if it's authorized)
- Degrees of knowledge:
  - Zero knowledge (Black box): The penetration testing team does not have any knowledge of the target and must start from ground zero
  - Partial knowledge (Grey box): The penetration testing team has some information about the target
  - Full knowledge (White box): The team has intimate knowledge of the target
  - Blind test: Defenders are not aware the testing is happening
  - Double-blind: Blind test to the assessors and network security staff is not notified
  - Targeted test: Focused test on specific areas of interest. For example, before a new application is rolled out, the team might test it for vulnerabilities before installing it into production
Three basic requirements:
- Meet with senior management to determine the goal of the assessment
- Document rules of engagement
  - Specific IP addresses/ranges to be tested
    - Any restricted hosts
  - A list of acceptable testing techniques
  - Times when testing is to be conducted
  - Points of contact for the penetration testing team, the target systems, and the networks
  - Measures to prevent law enforcement being called with false alarms
  - Handling of information collected by penetration testing team
- Get sign off from senior management
## Security Concepts in the Enterprise
### Information Security Triad
- Integrity: Assurance that data has not been modified
- Availability: Timely access to resources
- Confidentiality: Prevent unauthorized disclosures
### Legal and Regulatory Requirements
- Information security is the foundation of compliance with many laws regarding:
  - Privacy
  - Intellectual Property
  - Contracts and Procurements
  - Civil, Criminal, and Administrative laws and regulations
- Information governance is accountable for compliance with these laws and regulations
### Data Sovereignty
- Laws vary across jurisdictions
- Data sovereignty refers to the laws applicable to data because of the country in which it is physically located. The legal rights of data subjects and data protection requirements depend on the location in which their data is stored.
  - Data localization: Refers to a governmental policy prohibiting organizations from transferring data outside a specific location. It is a special use case of data sovereignty
  - Data residency: A decision by businesses to store data in a specific geographical location. Organizations might store data in a specific location to avoid legal requirements, take advantage of tax regimes, or for performance reasons. Once an organization chooses a location for its data, it is subject to data sovereignty - the laws applicable in that region.
### Unauthorized Use
- Ways to combat this:
  - Strong authentication
  - Encryption
  - Obfuscation, anonymization, tokenization, and masking
  - Organizational policies and layered defense
### Masking, Obfuscation, Anonymization, and Tokenization
- Obfuscation is the process of hiding, replacing, or omitting sensitive information.
  - Masking is the process of using specific characters to hide certain parts of a specific dataset. For instance, displaying asterisks for all but the last 4 digits of SSN
- Data Anonymization is the process of either encrypting or removing personally identifiable information from data sets so that the people whom the data describe remain anonymous
- Tokenization: Public cloud service can be integrated and paired with a private cloud that stores sensitive data. The data send to the public cloud is altered and contains a reference to the data residing in the private cloud
- Scoping: Limiting what is stored - the less I store, the less I have to protect
### Exfiltration of Data
- Attackers trying to extract data from their targets back to a machine controlled by the attacker
- **Data Loss Prevention Systems (DLPS) work to prevent this**
## Virtualization
- Virtualization allows logical isolation on multi-tenant servers
- Perfect environment for testing software
- Uses snapshots for quick and easy backup/restores
- Relies on the security of the Hypervisor
- Could allow attackers to target relevant components and functions to gain unauthorized access to data/systems/resources
### Hypervisor
- Allows multiple OS to share a single hardware host, with the appearance of each host having exclusive use of resources
- Type I Hypervisor runs directly on the hardware with VM resources provided by the Hypervisor
  - Also referred to as "bare metal"
  - VMWare ESXI, Citrix XenServer
  - Hardware based
- Type II Hypervisor runs on a host OS to provide virtualization services
  - VMWare workstation, and MS VirtualPC
  - Software based
### Application Virtualization
- Software is run on a server and is accessed by the client
- When an application is virtualized, the application has been previously captured as a "package" and is dynamically accessed on target machines when it is needed
- These virtual applications are the same applications that you might install on an operating system today, but thanks to virtualization and installation, configuration is no longer needed
### Security Concerns with Virtualization
- VM Escape
- Single interface for entry
- Physical redundancy
- Anti-malware for hosts and guests
- Unintentional bridging
## Cloud Computing
### Cloud Service Models
- SaaS (Software as a service)
  - SaaS provides the consumer the ability to use the provider's applications running on a cloud infrastructure. The applications accessible from various client devices through an interface like a web browser or a program interface
- PaaS (Platform as a service)
  - Provides the customer the capability to deploy onto the cloud infrastructure consumer-created or acquired applications created using programming languages, libraries, services, and tools supported by the provider
- IaaS (Infrastructure as a service)
  - The capability provided is to provision processing, storage, networks, and other fundamental computing resources where the consumer is able to deploy and run the software, including applications and operating systems. The consumer doesn't control the infrastructure but does control the OS, storage, deployed apps, and configuration settings
## Data Security in the Cloud
- Protecting data moving to and within the cloud
  - SSL/TLS/IPSec
- CASB (Cloud Access Security Brokers)
  - An enterprise management tool to mediate access to cloud services by users of all types of devices
    - Examples: Blue Coat, SkyHigh Networks, Microsoft Cloud App Security
  - CASBs provide visibility into how clients and nodes are using cloud resources
    - Single sign-on authentication from network to the cloud provider
    - Scans for malware or non-compliant devices
    - Monitors and audits user activities
    - Limit data exfiltration by preventing access to unauthorized cloud resources
- Protecting data in the cloud
  - Encryption
- Detection of data migration to the cloud
  - CLP
- Data dispersion
  - Data is replicated in multiple physical locations across your cloud
  - Used for higher availability
- Data fragmentation
  - Splitting a data set into smaller fragments (or shards) and distributing them across a large number of machines
- Crypto-shredding 
  - Renders data remnants in the cloud inaccessible
## Secure Application Development and Deployment
- Input Validation: Ensuring improper input is not allowed. It is especially well suited for the following vulnerabilities:
  - Code injection
  - Buffer overflow
  - XSS
  - XSRF
  - **Fuzzing is a technique of testing an application's input validation**
- Exception Handling: Errors should generate non-specific messages and ensure that no further security compromises happen
### Identity and Access Management
Defines the roles and access privileges of individual users and defines the processes for:
- Identification
- Authentication
- Authorization
- Accounting (Auditing)
## Resiliency
- Redundant Spares:
  - Redundant hardware
  - Available in the event that the primary device becomes unusable
  - Often associated with hard drives
  - How, warm, and cold swapped devices
  - SLAs
  - MTBF (Mean Time Between Failure)
  - MTTR (Mean Time to Repair)
- RAID (Redundant Array of Independent Devices):
  - RAID-0: Disk striping provides no redundancy or fault tolerance but provides performance improvement for read/write functions
  - RAID-1: Disk Mirroring provides redundancy but is often considered to be the least efficient usage of space
  - RAID-5: Disk Striping with Parity provides both fault tolerance and speed
  - RAID-6: Disk Striping with 2 parity disks
  - RAID-10 (RAID 0+1): Mirrored Stripe Set
- UPS (Uninterruptible Power Supply):
  - Issues to consider:
    - Size of load UPS can support
    - How long can it support this load (battery life)
    - Speed the UPS takes on the load when the primary power source fails
    - Physical space required
  - Desirable features:
    - Long battery life
    - Remote diagnostic software
    - Surge protection and line conditioning
    - EMI/RFI filters to prevent data errors caused by electrical noise
    - High MTBF values
    - Allow for automatic shutdown of the system
  - Primarily used to keep servers up until generators take over
## Redundancy of Data and Staff
### Backups
- Full Backup:
  - Archive bit is reset (Bit is set to 0)
- Incremental backup:
  - Backs up all files that have been modified since the last backup
  - Archive bit is reset
- Differential backup:
  - Backs up all files that have been modified since the last full backup
  - Archive bit is not reset
- Copy backup:
  - Same as full backup, but Archive bit is not reset
  - Use before upgrades or system maintenance
#### Issues
- Identify what needs to be backed up first
- Media rotation scheme:
  - Grandfather, Father, Son
  - Tower of Hanoi
- Backup schedule needs to be developed
- If restoring a backup after a compromise, ensure that the backup material does not contain the same vulnerabilities that were exploited
### Staff
- Eliminate single point of failure
- Cross training
- Job rotation
- Training and education
## Business Continuity and Disaster Recovery Planning
- BCP (Business Continuity Planning): Focuses on sustaining operations and protecting the viability of the business following a disaster until normal business conditions can be restored. The BCP is an umbrella term that includes many other plans, including the DRP. Long Term focused. Error exception and handling
- DRP (Disaster Recovery Planning): The goal is to minimize the effects of a disaster and to take the necessary steps to ensure that the resources, personnel, and business processes are able to resume operations in a timely manner. Deals with the immediate aftermath of the disaster and is often IT-focused. Short Term focused
## Hardening Systems
TODO
## Mobile Devices
TODO
## Embedded Systems
TODO
## Physical Security
TODO
## Cryptography
TODO
## Ports and Protocols
TODO
## Network Connectivity Devices
TODO
## Switching Concerns
TODO
## Routing
TODO
## Firewalls
TODO
## Additional Security Devices
TODO
## VPNs
TODO
## Wireless Configuration
TODO
## Authentication
TODO
## Crossover Error Rate
TODO
## Single Sign On
TODO
## Authorization and Access Control Model
TODO
## Incident Response
TODO
### Mitigation Techniques
TODO
### Forensics
TODO
### Chain of Custody and Order of Volatility
TODO
## Governance Risk and Compliance
### Frameworks and Standards
TODO
### Organizational Policies
TODO
### Information Security Risk Management
TODO
#### Risk Management Lifecycle
TODO
#### Risk Assessments
TODO
#### Risk Mitigation and Monitoring
TODO
#### Classification of Sensitive Data
TODO