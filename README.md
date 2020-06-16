# Public Bug Bounty Reports

### Since ~2020

Open for contributions from others as well, so please send a pull request if you can!

# Content
### raw
-  [Markdown](https://github.com/Robiq/Bug_Bounty_Reports/blob/master/reports.md)
-  [HTML](https://github.com/Robiq/Bug_Bounty_Reports/blob/master/reports.html)

### Rendered
-  [Markdown](https://robiq.github.io/Bug_Bounty_Reports/)
-  [HTML](https://robiq.github.io/Bug_Bounty_Reports/reports.html)

\# | Category | Description | Bounty | Program | URL
-- | --- | --- | --- | --- | ---
1 | IDOR | IDOR for order delivery address | $3000 | Mail.ru | https://hackerone.com/reports/723461
2 | IDOR | IDOR to change API-key description | $250 | Visma | https://hackerone.com/reports/809967
3 | SSRF | STUN SSRF | $3500 | Slack | https://hackerone.com/reports/333419
4 | SQLi | Blind SQLi through GET | $5000 | Mail.ru | https://hackerone.com/reports/786044 
5 | SQLi | Blind SQLi through GET | $5000 | Mail.ru | https://hackerone.com/reports/795291
6 | SQLi | Blind SQLi through GET | $3000 | Mail.ru | https://hackerone.com/reports/732430
7 | SQLi | SQLi | $2200 | Mail.ru | https://hackerone.com/reports/738740
8 | SQLi | Blind Boolean based SQLi through GET | $300 | Mail.ru | https://hackerone.com/reports/398131
9 | Buffer Overflow | Buffer Overflow　 | $1750 | Valve | https://hackerone.com/reports/458929
10 | Buffer Overflow | Buffer Overflow　 | $10,000 | Valve | https://hackerone.com/reports/542180 
11 | CSRF | CSRF in iOS app | $2940 | Twitter | https://hackerone.com/reports/805073
12 | Open redirect | Phishing Open Redirect | $560 | Twitter | https://hackerone.com/reports/781673
13 | DoS | DoS | $560 | Twitter | https://hackerone.com/reports/767458
14 | DoS | DoS | $560 | Twitter | https://hackerone.com/reports/768677 
15 | Information leak | Private key disclosed | $2000 | Slack | https://hackerone.com/reports/531032
16 | Request Smuggling | Request Smuggling | $6500 | Slack | https://hackerone.com/reports/737140
17 | Account Takeover | Brute force account takeover via recovery code | $3000 | Mail.ru | https://hackerone.com/reports/730067
18 | Information leak | Arbitrary memory leak through API call | $10,000 | Mail.ru | https://hackerone.com/reports/513236
19 | XSS | Blind Stored XSS | $600 | Mail.ru | https://hackerone.com/reports/659760 
20 | LFI (Information leak) | Local File Inclusion | $4000 | Starbucks | https://hackerone.com/reports/780021
21 | LFI | Arbitrary file inclusion & execution | $1000 | Valve | https://hackerone.com/reports/508894
22 | Information leak | Low impact information leak | $500 | HackerOne | https://hackerone.com/reports/826176
23 | Insufficient security controls | CORS misconfiguration | $1000 | SEMrush | https://hackerone.com/reports/235200
24 | Logic bug | Domain authority regex logic bug | $6000 | Google | https://bugs.xdavidhu.me/google/2020/03/08/the-unexpected-google-wide-domain-check-bypass/ 
25 | Privilege escalation | Abusing backup and restore function to escalate privileges | $1500 | Ubiquiti Inc | https://hackerone.com/reports/329659
26 | Privilege escalation | Arbritrary file deletion + DLL Hijacking leads to privilege escalation during install | $667 | Ubiquiti Inc | https://hackerone.com/reports/530967
27 | Information leak | Unauthenticated API endpoint leaking holiday schedule of employees in China | $4000 | Starbucks | https://hackerone.com/reports/659248
28 | Account takeover | Changing URL path from login to new-password allows merging victims store to attackers account | $7500 | Shopify | https://hackerone.com/reports/796956
29 | Improper access control | Unauthenticated API allows enumeration of user names & phone numbers | $500 | Razer | https://hackerone.com/reports/752443
30 | Authentication bypass | Auth bypass allowing access to support tickets | $1500 | Razer | https://hackerone.com/reports/776110
31 | Privilege escalation | Same as below, but change of email HAS to be completed before receiving the email verification request. Rewarded due to different root cause | $15,000 | Shopify | https://hackerone.com/reports/796808
32 | Privilege escalation | Takeover any shopify store by registering email, sending email verification request, changing email and confirming request chain | $15,000 | Shopify | https://hackerone.com/reports/791775
33 | Command injection | Abusing relative paths to run custom scripts during startup | $750 | Slack | https://hackerone.com/reports/784714
34 | Authentication bypass | View webcam and run code in context of any webpage in Safari | $75,000 | Apple | https://www.ryanpickren.com/webcam-hacking-overview
35 | XSS | Stored XSS through chat message | $300 | Vanilla | https://hackerone.com/reports/683792
36 | IDOR | IDOR allows enumeration of users with connected google analytics or the amount of calendars owned by a single user | $500 | SEMrush | https://hackerone.com/reports/797685
37 | Logic Error | Negative values allowed for price parameters allowed for free goods | $2111 | SEMrush | https://hackerone.com/reports/771694
38 | XSS | Stored XSS in customer chat | $1000 | Shopify | https://hackerone.com/reports/798599
39 | XSS | XSS through FB Group integration | $500 | Shopify | https://hackerone.com/reports/267570
40 | SQLi | Error-based SQLi through GET | $1500 | Mail.ru | https://hackerone.com/reports/790005
41 | SSRF | Blind SSRF | $150 | Mail.ru | https://hackerone.com/reports/120298
42 | IDOR | Leaking order information due to IDOR (No PII, only bought items) | $150 | Mail.ru | https://hackerone.com/reports/791289
43 | Code injection | PHP injection through unserialize() leading to code execution | $3000 | Mail.ru | https://hackerone.com/reports/798135
44 | Subdomain Takeover | Dangling AWS Record allowed zone transfer, leading to access to cookies and CORS, which could facilitate phishing attacks | $500 | Uber | https://hackerone.com/reports/707748
45 | Logic Error | No validation that user rated his own trips, meaning drivers could alter their ratings. | $1500 | Uber | https://hackerone.com/reports/724522
46 | LFI | Using PDF-generator and an iframe, one could export the PDF with arbritrary file content | $500 | Visma | https://hackerone.com/reports/809819
47 | XSS | Dom XSS in IE & Edge on main page | $1000 | ForeScout Technologies | https://hackerone.com/reports/704266
48 | Logic Error | Overwrite data as low privilege user, by renaming existing folder to the name of a folder you do not have access to | $250 | NextCloud | https://hackerone.com/reports/642515
49 | Improper access control | Unauthenticated API allowed an attacker to change hostname of device | $550 | UniFi Cloud | https://hackerone.com/reports/802079
50 | SQLi | SQLi through multiple parameters, but in unused service. Data exfiltration possible. | $2000 | Razer | https://hackerone.com/reports/777698
51 | SQLi | SQLi through get parameter allowed for data exfiltration from Thai users. | $2000 | Razer | https://hackerone.com/reports/768195
52 | SQLi | SQLi allowing for access to data on Thai server. | $2000 | Razer | https://hackerone.com/reports/781205
53 | SSRF | SSRF that could have lead to compromise of server and significant data breach | $2000 | Razer | https://hackerone.com/reports/777664
54 | Information leak | PHP file with source code exposed. No exploit. | $200 | Razer | https://hackerone.com/reports/819735
55 | CSRF | CSRF token with 24h lifetime, leading to possibility of connecting attackers paypal with victims shopify account | $500 | Shopify | https://hackerone.com/reports/807924
56 | Code Injection | MacOS client is vulnerable to low-privilege attacker injecting code into the application using dylib. This is due to lack of setting the Hardened Runtime capability in XCODE | $250 | NextCloud | https://hackerone.com/reports/633266
57 | Information leak | Cleartext storage of API keys & tokens. Very poorly handled. | $750 | Zenly | https://hackerone.com/reports/753868
58 | Improper access control | AWS Bucket access key transmitted in cleartext | $300 | BCM Messenger | https://hackerone.com/reports/764243
59 | Improper access control | Able to add paid function for 14 days for free | $200 | Coda | https://hackerone.com/reports/777942
60 | XSS | Blind XSS in admin panel through a partner's superuser name | $750 | Mail.ru | https://hackerone.com/reports/746497
61 | XSS | Blind XSS in admin panel through a partner's superuser name (Same issue, different endpoint) | $750 | Mail.ru | https://hackerone.com/reports/746505
62 | SSRF | SSRF & Local File Read via photo upload | $6000 | Mail.ru | https://hackerone.com/reports/748128
63 | SSRF | SSRF & Local File Read via photo retrieving functionality | $6000 | Mail.ru | https://hackerone.com/reports/748069
64 | SSRF | SSRF & Local File Read via photo editor | $6000 | Mail.ru | https://hackerone.com/reports/748123
65 | Logic Error | A partner account with manager role could withdraw money from driver's account | $8000 | Mail.ru | https://hackerone.com/reports/751347
66 | XSS | Reflected XSS through XML Namespace URI | $500 | Mapbox | https://hackerone.com/reports/780277
67 | Code Injection | HTML Injection for IE only | $500 | Mail.ru | https://hackerone.com/reports/757100
68 | DoS | Cache poisoning CORS allow origin header | $550 | Automattic | https://hackerone.com/reports/591302
69 | IDOR | Remote wipe of other users device | $500 | Nextcloud | https://hackerone.com/reports/819807
70 | SSRF | GitLab local instance SSRF bypass through DNS Rebinding in WebHooks | $3500 | GitLab | https://hackerone.com/reports/632101
71 | LFI | openStream called on java.net.URL allows access to local resources when passing in file:// or jar:// | $1800 | GitHub Security Lab | https://hackerone.com/reports/844327
72 | Logic Bug | Not checking if LINUX privilege is successfully dropped leads to increased attack surface | $1800 | GitHub Security Lab | https://hackerone.com/reports/845729
73 | SQLi | Arbitrary SQL queries via DocID parameter of Websocket API | $1800 | GitHub Security Lab | https://hackerone.com/reports/854439
74 | Logic Bug | Account takeover through link injection in contact form | $1000 | Insolar | https://hackerone.com/reports/786741
75 | Information leak | Ability to see other shops product title, only if they are using a particular app and has an attachment | $500 | Shopify | https://hackerone.com/reports/848625
76 | XSS | Reflected XSS on API Server (No regular users browsing the page) | $250 | Razer | https://hackerone.com/reports/791941
77 | Brute Force | Counter-specific (?) password was not protected against brute force attacks | $150 | Mail.ru | https://hackerone.com/reports/754536
78 | Authentication bypass | Knowing the victims phone number allowed access to partial information about the victims travel. Payment type, profile information, etc. | $8000 | Mail.ru | https://hackerone.com/reports/772118
79 | Information leak | API endpoint disclosed e-mails of subscribed users | $250 | Mail.ru | https://hackerone.com/reports/703086
80 | DoS | DoS & Unsafe Object creation through JSON parsing | $500 | Ruby | https://hackerone.com/reports/706934
81 | Logic Error | Session Expiration is not enforced during signup. Bypass can be done by deleting HTML element blocking progress | $100 | Visma | https://hackerone.com/reports/810400
82 | Subdomain Takeover | Subdomain takeover due to expired / unclaimed Hubspot instance | $2500 | Roblox | https://hackerone.com/reports/335330
83 | Information leak | Endpoint vulnerable to Heartbleed | $1500 | Uber | https://hackerone.com/reports/304190
84 | RCE | LFI through Path Traversal in image-tag in Markdown. Disclosure of local files leads to disclosure of secret, which can be used to achieve RCE through deserialization | $20,000 | GitLab | https://hackerone.com/reports/827052
85 | Prototype Pollution | Simple prototype pollution due to improper handling of zipObjectDeep | $250 | Node.js Third Party Modules (lodash) | https://hackerone.com/reports/712065
86 | Information disclosure | Session is not properly invalidated after logging out. When creating a store before upgrading your account, visitors are required to enter a password. This password is disclosed after logging out, when visiting a certain link. | $500 | Shopify | https://hackerone.com/reports/837729
87 | IDOR | Able to bypass ban restrictions through path normalization. APIs are also unrestricted | $800 | Roblox | https://hackerone.com/reports/703058
88 | Phishing | Link url falsification by altering post message | $250 | Slack | https://hackerone.com/reports/481472
89 | Information leak | Leaking (unrestricted?) Google API key | $150 | Identify | https://hackerone.com/reports/724039
90 | Improper access control | Read-only team members can read all properties of webhooks, through graphql | $0 | HackerOne | https://hackerone.com/reports/818848
91 | DoS | DoS through sending large message to the server | $500 | Roblox | https://hackerone.com/reports/679907
92 | IDOR | Access to log files based on IDOR through exposed signature in Razer Pay Android App | $500 | Razer | https://hackerone.com/reports/754044
93 | Path Traversal | Misconfiguration when handling URI paths allowed for docroot path traversal giving access to non-sensitive data usually not accessible to users | $500 | Starbucks | https://hackerone.com/reports/844067
94 | Improper Certificate Validation | Client side traffic hijacking allowed for user data interception (Local?) | $750 | Razer | https://hackerone.com/reports/795272
95 | Improper authorization | The Razer Pay backend server could be exploited to obtain transaction details from another user | $500 | Razer | https://hackerone.com/reports/754339
96 | SQLi | Razer Pay API was vulnerable to SQLi exposing user information | $2000 | Razer | https://hackerone.com/reports/811111
97 | Improper authorization | Reverse engineering the Android app allowed for bypassing the signatures in place to prevent parameter tampering, discovering a variety of IDOR issues | $1000 | Razer | https://hackerone.com/reports/753280
98 | HTTP Response Splitting | Limited CRLF injection allowed for manipulation of cookies | $150 | Mail.ru | https://hackerone.com/reports/838682
99 | IDOR | Issue with the marketplace due to length restriction in choosing hashing function | $5000 | SEMrush | https://hackerone.com/reports/837400
100 | SSRF | SSRF & LFI in Site Audit due to lack of connection protocol verification | $2000 | SEMrush | https://hackerone.com/reports/794099
101 | SSL Downgrade | Possible to temporarily downgrade a victim from HTTPS to HTTP in Firefox. Required victim clicking a link and had a very short timeframe to be successful | $500 | Uber | https://hackerone.com/reports/221955
102 | XSS | Reflected XSS due to outdated Wordpress installation lead to exposure of sensitive form data and user data | $4000 | Uber | https://hackerone.com/reports/340431
103 | Open Redirect | Open redirect in get parameter | $50 | Unikrn | https://hackerone.com/reports/625546
104 | DoS | Bypassing character limitation on ´Moments´ feature and creating many of them leads to DoS | $560 | Twitter | https://hackerone.com/reports/819088
105 | CRLF Injection | CRLF injection in urllib | $1000 | Python (IBB) | https://hackerone.com/reports/590020
106 | Subdomain Takeover | Out of scope, no impact subdomain takeover of uptimerobot page | $100 | BTFS | https://hackerone.com/reports/824909
107 | SQLi | Blind Boolean-based SQLi in Razer Gold TH | $1000 | Razer | https://hackerone.com/reports/790914
108 | SSRF | SSRF allowing port scanning of localhost through host header injection | $300 | TTS Bug Bounty | https://hackerone.com/reports/272095
109 | Cryptographic Issues | A variety of WPA3 issues related to cryptography and logic | $750 | The Internet | https://hackerone.com/reports/745276
110 | XSS | Reflected XSS on resources.hackerone.com | $500 | HackerOne | https://hackerone.com/reports/840759
111 | Information leak | Un-minified JS code disclosed on some pages | $250 | Imgur | https://hackerone.com/reports/845677
112 | XSS | Self-XSS to normal XSS by bypassing X-Frame-Options to automatically execute JS through loading content through iframes | $250 | Pornhub.com | https://hackerone.com/reports/761904
113 | IDOR | A partner account could access another partner's driver data through an IDOR | $1500 | mail.ru | https://hackerone.com/reports/747612
114 | IDOR | A partner account could access information about other partners through an IDOR | $1500 | mail.ru | https://hackerone.com/reports/746513
115 | IDOR | A partner with manager role could takeover a drive's account belonging to a different partner | $8000 | mail.ru | https://hackerone.com/reports/751281
116 | XSS | Stored XSS on messages to drivers through the operator interface | $500 | mail.ru | https://hackerone.com/reports/751263
117 | Code Execution | PHP Code Execution through image upload functionality | $3000 | mail.ru | https://hackerone.com/reports/854032
118 | Improper Access Control | Delete projects from archived companies set to Read-Only. | $100 | Visma | https://hackerone.com/reports/849157
119 | Information leak | Account takeover due to leaking auth URLs on google & leaking OTP in API response | $500 | Badoo | https://hackerone.com/reports/746186
120 | XSS | Stored XSS through file upload (.pdf → JS) | $250 | Visma | https://hackerone.com/reports/808862
121 | Information leak | 404-page leaks all headers | $500 | HackerOne | https://hackerone.com/reports/792998
122 | CSRF | Friends Only account mode could be toggled through CSRF | $250 | Mail.ru | https://hackerone.com/reports/448928
123 | Subdomain Takeover | Possible due to wildcard pointing to uberflip domain | $500 | HackerOne | https://hackerone.com/reports/863551
124 | DoS | Improper error handling leads to DoS and service failure in case of supplying invalid "Redirect_URI" parameter | $1000 | GitLab | https://hackerone.com/reports/702987
125 | Information leak | Private program invites can disclose emails of any user invited by using username | $7500 | HackerOne | https://hackerone.com/reports/807448
126 | SSRF | SSRF through notification configuration. Requires admin privileges | $300 | Phabricator | https://hackerone.com/reports/850114
127 | Improper Access Control | Read-only user without access to payroll, can still access the data by visiting the URL directly | $250 | Visma | https://hackerone.com/reports/838563
128 | XSS | Code does not sufficiently escape template expressions, allowing for XSS | $500 | Ruby On Rails | https://hackerone.com/reports/474262
129 | Information leak | Potentially sensitive information leaked through debug interface | $150 | Mail.ru | https://hackerone.com/reports/748925
130 | Misconfiguration | Network restrictions on admin interface could be bypassed using alternate hostnames | $150 | Mail.ru | https://hackerone.com/reports/749677
131 | Request Smuggling | Request smuggling poisoning users using Host header injection | $750 | TTS | https://hackerone.com/reports/726773
132 | Lack of security mechanisms | Lack of user warning when opening potentially dangerous files from the chat window | $250 | Mail.ru | https://hackerone.com/reports/633600
133 | XSS | Reflected XSS in investor relations website due to unsanitized user input | $350 | Razer | https://hackerone.com/reports/801075
134 | SQLi | Blind SQLi due to no input sanitization on "Top Up" function in Razer Gold TH service | $1000 | Razer | https://hackerone.com/reports/789259
135 | Subdomain Takeover | Subdomain takeover | $250 | Razer | https://hackerone.com/reports/810807
136 | Open redirect | Open redirect in login flow | $150 | TTS | https://hackerone.com/reports/798742
137 | Race Condition | Race condition in email verification that awards in-game currency, leading to similar impact as payment bypass | $2000 | InnoGames | https://hackerone.com/reports/509629
138 | Account Takeover | Links on in-game forum leaks referer header, which contains CSRF token. The page also embeds links with the cookie value on the page. Utilizing self-xss combined with CSRF-token, you can grab cookie from DOM and send it to attacker resulting in Account Takeover | $1100 | InnoGames | https://hackerone.com/reports/604120
139 | XSS | Reflected XSS due to insufficient input sanitation. Could allow for account takeover or user session manipulation. | $1900 | PayPal | https://hackerone.com/reports/753835
140 | XSS | Stored XSS through bypass of file type upload limit by 0-byte. Uploading a xx.html%00.pdf with JS will work like a stored XSS when accessed | $250 | Visma | https://hackerone.com/reports/808821
141 | Improper Authentication | An issue in how Cloudflare's authoritative DNS server processes requests with ":" in it. This allows an attacker to spoof NXDOMAINs within safe zones. | $400 | Open-Xchange | https://hackerone.com/reports/858854
142 | Improper Access Control | Can reply or delete replies from any users in any public group, without joining said group. (Buddypress) | $225 | WordPress | https://hackerone.com/reports/837256
143 | Privilege Escalation | Author role has access to edit, trash and add new items within the BuddyPress Emails. | $225 | WordPress | https://hackerone.com/reports/833782
144 | CSRF | Profile field CSRF allows for deleting any field in BuddyPress | $225 | WordPress | https://hackerone.com/reports/836187
145 | Privilege Escalation | IDOR + Changing parameter from "Moderator" to "Admin" leads to privilege escalation | $225 | WordPress | https://hackerone.com/reports/837018
146 | Privilege Escalation | Chaining 5 vulnerabilities leads to privilege to root, by: Symlink attack combined with race condition leads to executing malicious code | $500 | NordVPN | https://hackerone.com/reports/767647
147 | XSS | Reflected XSS evading WAF + confirming insufficient fix | $1000 | Glassdoor | https://hackerone.com/reports/846338
148 | Information leak | New retest functionality discloses existence of private programs through having the tag added to the program description | $500 | HackerOne | https://hackerone.com/reports/871142
149 | XSS | Outdated PDF.js allows for XSS using CVE-2018-5158 | $100 | Nextcloud | https://hackerone.com/reports/819863
150 | DoS | DoS due to having a large amount of groups and sending a tampered request (Changed Accept-Encoding & User-Agent) | $500 | HackerOne | https://hackerone.com/reports/861170
151 | XSS | Stored XSS in user profile | $200 | QIWI | https://hackerone.com/reports/365093
152 | Logic Bug | Service time expiry validation bypass leads to unlimited use due to bypassing licensing time checks | $400 | NordVPN | https://hackerone.com/reports/865828
153 | Improper Access Control | Privilege escalation through improper access control on /membership/ endpoint | $500 | Helium | https://hackerone.com/reports/809816
154 | IDOR | Sending invitations is vulnerable to IDOR attack, resulting in being able to invite any account as administrator of a organization, by knowing the organizations UUID | $100 | Helium | https://hackerone.com/reports/835005
155 | Improper Access Control | Dcoker Registry API v2 exposed through HTTP, allowing for dumping & poisoning of docker images. | $2000 | Semmle | https://hackerone.com/reports/347296
156 | Code Injection | CodeQL query to detect JNDI injections | $2300 | GitHub | https://hackerone.com/reports/892465
157 | Information leak | GraphQL query can disclose information about undisclosed reports to the HackerOne program due to the retest feature | $2500 | HackerOne | https://hackerone.com/reports/871749
158 | Logic Bug | CodeQL query to detect improper URL handling | $1800 | GitHub | https://hackerone.com/reports/891268
159 | Information leak | CodeQL query to detect Spring Boot actuator endpoints | $1800 | GitHub | https://hackerone.com/reports/891266
160 | Logic Bug | CodeeQL query to detect incorrect conversion between numeric types in GOLang | $1800 | GitHub | https://hackerone.com/reports/891265
161 | Improper Access Control | Certain API methods were not properly restricted and leaked statistics about arbitrary domains | $400 | Mail.ru | https://hackerone.com/reports/831663
162 | Code Injection | Using chat commands functions like "/calculate 1+1" is possible, but it can be abused by using BASH syntax for executing commands "/calculate $(ping attacker.com)", leading to arbitrary code execution | $3000 | Nextcloud | https://hackerone.com/reports/851807
163 | Privilege Escalation | Can invite members to a "clan" even when the user does not have access to that function | $550 | InnoGames | https://hackerone.com/reports/511275
164 | XSS | AirMax software was vulnerable to Reflected XSS on multiple end-points and parameters | $150 | Ubiquiti inc. | https://hackerone.com/reports/386570
165 | Privilege Escalation | Changing email parameter allows privilege escalation to admin | $100 | Helium | https://hackerone.com/reports/813159
166 | Information leak | CodeQL query to detect logging of sensitive data | $500 | GitHub | https://hackerone.com/reports/886287
167 | CSRF | CSRF is possible in the AirMax software on multiple endpoints leading to possible firmware downgrade, config modification, file or token ex-filtration etc. | $1100 | Ubiquiti inc. | https://hackerone.com/reports/323852
168 | Account Takeover | No brute-force protection on SMS verification endpoint lead to account takeover | $1700 | Mail.ru | https://hackerone.com/reports/744662
169 | IDOR | API allowed for leaking information on job seekers / employers through IDOR | $500 | Mail.ru | https://hackerone.com/reports/743687
170 | XSS | Reflected XSS through URI on 404 page | $300 | Mail.ru | https://hackerone.com/reports/797717
171 | SSRF | SSRF through using functionality from included library that should be disabled | $10,000 | GitLab | https://hackerone.com/reports/826361
172 | Information leak | Insufficient verification leads to ability to read sensitive files | $10,000 | GitLab | https://hackerone.com/reports/850447
173 | Improper Authentication | Could impersonate and answer tickets belonging to other users | $550 | InnoGames | https://hackerone.com/reports/876573
174 | Subdomain Takeover | Subdomain takeover of iosota.razersynapse.com | $200 | Razer | https://hackerone.com/reports/813313
175 | XSS | Reflected xss through cookies on ftp server for Thai employees | $375 | Razer | https://hackerone.com/reports/748217
176 | XSS | Out of scope DOM XSS leading to impact on account security for in scope asset. Only applicable to IE and Edge. | $750 | Rockstar Games | https://hackerone.com/reports/663312
177 | SQLi | Search function was crashable disclosing error logs with useful information for other potential attacks. | $250 | Rockstar Games | https://hackerone.com/reports/808832
178 | Open Redirect | Could potentially leak sensitive tokens through referer header on GTA Online sub-site.  | $750 | Rockstar Games | https://hackerone.com/reports/798121
179 | XSS | DOM XSS in GTA Online feedback endpoint. Other issues with the same root cause was also found on the same site. | $1250 | Rockstar Games | https://hackerone.com/reports/803934
180 | DoS | In email verification emails, the unique number is assigned sequentially, meaning you can invalidate all future registrations by visiting the following URL. Ex: confirmmail/1/jfaiu -> confirmmail/2/jfaiu | $150 | Vanilla | https://hackerone.com/reports/329209
181 | Information leak | External images could be referenced in the screenshot utility feature, possibly leading to FaceBook OAUTH token theft | $500 | Rockstar Games | https://hackerone.com/reports/497655
182 | XSS | Dom XSS on main page achieved through multiple minor issues, like path traversal and open redirect | $850 | Rockstar Games | https://hackerone.com/reports/475442
183 | XSS | Stored XSS through demo function in multiple parameters using javascript scheme | $750 | Shopify | https://hackerone.com/reports/439912
184 | Improper access control | After removing admin access from an account, it can still make changes with admin permissions until logged out. The account can also still make changes to embedded apps, but this is by design. | $1000 | Shopify | https://hackerone.com/reports/273099
185 | CSRF | Account takeover on social club by using CSRF to link an account to the attackers facebook account, leading to the ability to login as the victim | $1000 | Rockstar Games | https://hackerone.com/reports/474833
186 | XSS | Reflected XSS due to decoding and executing code after the last "/" on GTAOnline/jp.  | $750 | Rockstar Games | https://hackerone.com/reports/507494
187 | Open Redirect | Open Redirect on the support page, impacting the mobile page | $750 | Rockstar games | https://hackerone.com/reports/781718
188 | XSS | DOM XSS on GTAOnline. Regressed Directory Traversal and new XSS issue | $750 | Rockstar games | https://hackerone.com/reports/479612
189 | Race Condition (TOCTOU) | Can click "This Rocks" (like) button any number of times, allowing an attacker to fill up the victims notification feed | $250 | Rockstar games | https://hackerone.com/reports/474021
190 | XSS | DOM XSS in the video section of GTAOnline page through returnurl-parameter, only exploitable on non-English versions.  | $750 | Rockstar games | https://hackerone.com/reports/505157
191 | CSRF | CSRF on login page only, due to processing credentials before checking for CSRF protections. This is also only valid when forcing non 4xx responses from the server | $500 | HackerOne | https://hackerone.com/reports/834366


