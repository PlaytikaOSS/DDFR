# DDFR - Dangling Domains Finder

> A lightweight Python utility to detect dns records that are suspected as dangling.

---

## Description
Do you have a large cloud environment with many services and VMs?
Then probably some of your domain names are pointing to unclaimed IP addresses due to improper deprecation of services/VMs.

**DDFR to the rescue!**

Basically, the tool gets a list of your DNS records and checks if the pointed IPs belongs to your cloud accounts.

### Behind the scenes

1. You provide DDFR with a list of your DNS records _(see Usage section)_.
1. You provide DDFR with a list of all your registered cloud IPs in one of the following ways:
    - Allow DDFR to **automatically collect** all of your registered IPs from Palo Alto's Prisma Cloud product.
    - **Manually provide** a file with your registered cloud IPs.
1. DDFR compares the lists to see if there are domains pointing to IPs not owned by you and therefore
  **suspected as dangling**.
    
    _**NOTE:** DDFR also provides you with a mechanism to reduce false positives, read more about it below._
1. DDFR generates a report of the suspected DNS records.

---

## Installation
### Prerequisites
- [Optional] To pull records from Prisma Cloud, fill in the required environment variables:
```bash
export PRISMA_API_KEYID = your-value-here
export PRISMA_API_SECRET = your-value-here
export PRISMA_URL = your-value-here
```
  
### PIP (recommended)
```bash
pip install ddfr
```

### Manual
```bash
git clone https://github.com/playtika/DDFR.git
cd DDFR
pip install .
```
  

---

## Recommended Python Version
DDFR was developed and tested only with __Python3__.

---

## Usage

Short Form    | Long Form            | Description
------------- | -------------------- |-------------
-d            | --domains            | Full path to a file contains your DNS records
-i            | --ips                | Full path to a file contains your owned ips (if non-existent will pull from prisma) 
-cn           | --ssl-common-names   | Full path to a file contains key words that should appear in your CNs (for reducing false positives)
-r            | --ranges             | Full path to a file contains AWS ip ranges
-o            | --output             | Full path to output directory



Domains file needs to be in the following format (JSON):
```json
[{"name": "domain name", "record_type": "DNS type (CNAME,A)", "record_value": "(ip,ec2 domain name)", "source": "dns management system/provider"}]
```

## Usage Examples
- Pull ips form prisma\
  ```ddfr -d "domains.json" -r "aws-ranges.txt" -cn "common-names.txt"```
- Receive ips from a file\
  ```ddfr -d "domains.json" -r "aws-ranges.txt" -cn "common-names.txt" -i "my-ips.txt"```

---
## The Motivation for Creating DDFR
Subdomains takeovers have become a popular technique used by attackers and bug bounty hunters.

DNS records that points to unclaimed IP addresses is a specific use case of this attack that is pretty hard to catch
(for both blue and red teams).

**As a red-teamer**, this kind of takeovers are hard to find as they require many resources to perform a successful attack
(bruteforcing VMs IP addresses attached by the cloud providers) and reverse DNS lookup.

**As a blue-teamer**, companies nowadays have thousands of DNS records which makes it extremely hard to find manually. 

By being able to pull your company's DNS records from your DNS management system be it AWS Route53 or any other,
you can proactively look for those dangling records with this tool and mitigate these takeovers.

---
## Roadmap
- Automate AWS ranges fetching
- Support for more cloud providers

---
## Contributing
Feel free to fork the repository and submit pull-requests.

---

## License

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
