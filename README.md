# 🛡️ AWS CodeBuild Security Auditor

This tool audits **AWS CodeBuild projects** for common security risks.  
It checks for misconfigured webhooks, overly permissive IAM roles, and insecure network configurations to help strengthen your CI/CD pipeline security.

---

## ✨ Features

- **CodeBuild Runner Audit (`runner` mode)**  
  - Detects runner projects (self-hosted GitHub Actions runners, GitLab runners, etc.)  
  - Audits **webhook filters & branch protections**  
  - Validates **IAM service roles** (assume role policy, admin permissions, inline policies)  
  - Reviews **security group rules** for excessive permissions  

- **OIDC IAM Role Audit (`oidc` mode)**  
  - Inspects OIDC role trust policies  
  - Flags **wildcard or overly broad conditions** in `sub` claims  
  - Highlights risks like org-wide or repo-wide access  
  - Provides **recommendations** for safe OIDC trust policies 

---

## 📦 Requirements
- Python 3.7+
- [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)  
- AWS credentials configured (via AWS CLI, environment variables, or IAM role)

---

## Install dependencies:
```bash
pip install boto3
```

---

## Required Permissions

The IAM role or user running this tool must have the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codebuild:ListProjects",
        "codebuild:BatchGetProjects",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "ec2:DescribeSecurityGroups",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```
---
## 🚀 Usage

Run the tool in one of two modes depending on your audit needs:

### 1. CodeBuild Security Audit (`runner` mode)
This mode audits **all CodeBuild projects** in the current AWS account.  
It checks for runner projects, verifies webhook filter protections, inspects IAM service roles, and analyzes security groups.

```bash
python3 audit_codebuild.py runner
```

### 2. OIDC Role Trust Policy Audit (`oidc` mode)

This mode audits the **trust policy of an IAM role** that uses OIDC (for example, GitHub Actions → AWS integration).  
It identifies risky configurations such as **wildcard patterns**, **org-wide repository access**, and **branch-wide permissions**.

#### Command
```bash
python3 audit_codebuild.py oidc <role_name>
```
---

## Output Example
![Sample Output](https://github.com/guyHavia/codebuild-sa/blob/788e787ed4fb64905cd507a4bc47c8f311d010a1/images/output_example.png)
