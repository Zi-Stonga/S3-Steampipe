# AWS IAM Security Auditing with Steampipe
 
A practical security audit project demonstrating how to use [Steampipe](https://steampipe.io/) to query AWS IAM credential reports using SQL, identify misconfigurations, and produce actionable remediation findings.
 
---
 
## Overview
 
This project walks through setting up Steampipe with the AWS plugin and running a series of SQL queries against `aws_iam_credential_report` to surface common IAM security issues including:
 
- Root account usage and MFA status
- Stale or unused passwords (>90 days)
- Users with both console access and active access keys
- MFA enforcement gaps
---
 
## Prerequisites
 
- [Steampipe v1.0.1+](https://steampipe.io/downloads) installed
- AWS CLI configured with valid credentials (access key + secret)
- AWS IAM permissions to generate and read credential reports (`iam:GenerateCredentialReport`, `iam:GetCredentialReport`)
---
 
## Setup
 
### 1. Install Steampipe
 
```bash
# Linux/macOS
/bin/sh -c "$(curl -fsSL https://steampipe.io/install/steampipe.sh)"
 
# Verify installation
steampipe -v
```
 
### 2. Install the Steampipe Plugin (self-referential registry query)
 
```bash
steampipe plugin install steampipe
steampipe query "select name from steampipe_registry_plugin;"
```
 
### 3. Install the AWS Plugin
 
```bash
steampipe plugin install aws
```
 
Installed version: `aws@latest v1.5.0`  
Documentation: https://hub.steampipe.io/plugins/turbot/aws
 
### 4. Configure AWS Credentials
 
Ensure your AWS credentials are configured via `~/.aws/credentials` or environment variables before launching the interactive client.
 
---
 
## Usage
 
Launch the Steampipe interactive client:
 
```bash
steampipe query
```
 
Then run the queries below.
 
---
 
## Security Audit Queries
 
### List All IAM Users (Credential Report)
 
```sql
select * from aws_iam_credential_report;
```
 
Returns all IAM users including the root account, their ARNs, creation times, and credential metadata.
 
---
 
### Check Root Account Password Usage
 
```sql
select
  user_name,
  password_last_used,
  age(date(current_timestamp), date(password_last_used)) as pw_last_used
from aws_iam_credential_report
where user_name = '<root_account>';
```
 
**Finding:** Root account shows `<null>` for `password_last_used`, no direct console logins recorded, which is good practice.
 
---
 
### Check Root Account MFA Status
 
```sql
select
  user_name,
  mfa_active
from aws_iam_credential_report
where user_name = '<root_account>';
```
 
**Finding:** `mfa_active = false`: **Root MFA is not enabled. This is a critical misconfiguration.**
 
---
 
### Identify Users with Stale or Never-Used Passwords
 
```sql
select
  user_name,
  password_enabled,
  password_last_used,
  age(date(current_timestamp), date(password_last_used)) as last_used_age
from aws_iam_credential_report
where user_name != '<root_account>'
  and password_enabled
  and (
    password_last_used is null
    or (date(current_timestamp) - date(password_last_used)) > 90
  );
```
 
**Finding:** `sarah.johnson` and `john.smith` have console passwords enabled but have **never logged in** (`password_last_used = null`).
 
---
 
### Identify Users with Both Console Access and Active Access Keys
 
```sql
select
  user_name,
  password_enabled,
  access_key_1_active,
  access_key_2_active
from aws_iam_credential_report
where password_enabled
  and (
    access_key_1_active
    or access_key_2_active
  );
```
 
**Finding:** `john.smith` and `sarah.johnson` have both password-based console access and active programmatic access keys, a dual-credential risk.
 
---
 
## Findings Summary
 
| Finding | Severity | Affected Resource |
|---|---|---|
| Root MFA not enabled |  Critical | `<root_account>` |
| Users with stale/unused passwords |  High | `john.smith`, `sarah.johnson` |
| Users with dual credentials (console + keys) |  High | `john.smith`, `sarah.johnson` |
| Root account password last used: null |  Informational | `<root_account>` |
 
---
 
## Recommendations
 
### 1. Enable MFA on the Root Account Immediately
The root account has `mfa_active = false`. This is one of the highest-risk misconfigurations in AWS. Enable hardware or virtual MFA on the root account and restrict its use to break-glass scenarios only.
 
### 2. Disable or Remove Unused Console Passwords
`john.smith` and `sarah.johnson` have never used their console passwords. If console access is not required for these users, disable it via:
```bash
aws iam delete-login-profile --user-name john.smith
aws iam delete-login-profile --user-name sarah.johnson
```
 
### 3. Enforce a Password Policy with Inactivity Controls
Set an IAM account password policy that disables passwords after 90 days of inactivity and enforces complexity requirements.
 
### 4. Separate Console and Programmatic Access
Users should not hold both active access keys and console passwords unless there is a documented business need. Prefer role-based access (assume-role) over long-lived access keys for human users.
 
### 5. Rotate or Deactivate Unused Access Keys
Audit `access_key_1_last_used` and `access_key_2_last_used` for all users. Deactivate keys unused for more than 90 days.
 
### 6. Restrict CredentialsReportUser Permissions
The `CredentialsReportUser` account exists specifically to generate credential reports. Confirm it has only the minimum required permissions (`iam:GenerateCredentialReport`, `iam:GetCredentialReport`) and no console login profile.
 
### 7. Implement AWS Config Rules or Security Hub
Automate ongoing detection of these issues using:
- **AWS Security Hub** CIS AWS Foundations Benchmark controls
- **AWS Config** managed rules like `iam-root-access-key-check`, `mfa-enabled-for-iam-console-access`
- **Steampipe scheduled queries** or Powerpipe dashboards for continuous visibility
---
 
## Project Structure
 
```
.
├── README.md
└── queries/
    ├── credential_report_all.sql
    ├── root_password_usage.sql
    ├── root_mfa_check.sql
    ├── stale_passwords.sql
    └── dual_credentials.sql
```
 
---
 

 
## References
 
- [Steampipe Documentation](https://steampipe.io/docs)
- [AWS IAM Credential Report](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Security Hub IAM Controls](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html)
