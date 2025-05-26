# Identity Compromise Investigation: Impossible Travel & Unfamiliar Sign-In

## Objective

Conducted an investigation using Splunk and Microsoft 365 Audit Logs to identify potential account compromises by detecting impossible travel and unfamiliar sign-in activities.

## How I Conducted the Investigation

### Step 1: Reviewing Audit Logs

I started by accessing the Microsoft 365 Unified Audit Logs through Splunk, focusing specifically on user login events (`Operation=UserLoggedIn`). This allowed me to quickly identify relevant log entries.

### Step 2: Removing Non-User Entries

To make my analysis accurate, I filtered out any system-generated logs (`UserType!=4`) so I could concentrate solely on user-related activities.

### Step 3: Checking IP Addresses

I extracted IP addresses from fields like `ActorIpAddress` and `ClientIP`. Using the OSINT tool ipinfo.io, I performed geolocation checks to determine where these logins originated from.

### Step 4: Detecting Impossible Travel

While analyzing login locations, I discovered a suspicious scenario involving a user named "JChan," who logged in from Vancouver, Canada, and then just minutes later from Singapore. This scenario indicated potential impossible travel and raised immediate security concerns.

### Step 5: Investigating Suspicious Activity

Digging deeper, I analyzed activities associated with the suspicious Singapore IP (188.214.125.138). I identified several distinct malicious mailbox operations:

* **Unauthorized Email Forwarding Rule:** Created a mailbox rule forwarding emails from internal user `schan` to an external email (`stoicellis@imcourageous.com`). Emails were automatically marked as read and moved to the Deleted Items folder.
* **Email Access:** Accessed multiple sensitive emails, particularly focusing on drafts.
* **Email Deletion:** Deleted critical draft emails, notably targeting sensitive financial information.
* **Sending Malicious Emails:** Sent targeted phishing emails, including one titled "URGENT: Client Bank Account" with a malicious attachment (`NEW-BANK-ACCOUNT.pdf`).

### Step 6: Identifying Sensitive Email Access

Further investigation revealed specific sensitive emails accessed by the attacker, including:

* Draft titled "RE: First Invoice of the month!"
* Draft titled "URGENT: Client Bank Account"

## Summary of Investigation

* **Compromised Account:** `jchan@7pd6vr.onmicrosoft.com`
* **Suspicious IP Address:** 188.214.125.138 (Singapore)
* **Malicious Activities Detected:**

  * Created unauthorized email forwarding rules.
  * Accessed and deleted sensitive draft emails.
  * Sent targeted phishing emails containing malicious attachments.

## Recommended Actions

* Immediately reset credentials and revoke active sessions for the compromised account.
* Remove unauthorized email forwarding rules and mailbox settings.
* Conduct comprehensive searches to find additional indicators of compromise.
* Strengthen security monitoring and implement alerts for impossible travel and unusual login activities.

## Tools Used

* **Splunk:** Used for comprehensive log analysis and event correlation.
* **Microsoft 365 Audit Logs:** Provided detailed insights into user actions.
* **ipinfo.io:** Assisted in IP address geolocation and threat assessment.

---

This hands-on investigative approach demonstrates my capabilities in effectively handling security incidents, conducting detailed log analyses, and swiftly responding to cybersecurity threats.
