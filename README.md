# 🛡️ AWS CodeBuild Security Auditor

This tool audits **AWS CodeBuild projects** for common security risks.  
It checks for misconfigured webhooks, overly permissive IAM roles, and insecure network configurations to help strengthen your CI/CD pipeline security.

---

## ✨ Features
- 🔍 **Detects runner projects** (self-hosted GitHub/GitLab/CI runners in CodeBuild)
- 🔒 **Validates webhook filters**:
  - Ensures branch protection is in place
  - Flags permissive filter groups that can bypass restrictions
- 👤 **Audits IAM service roles**:
  - Verifies assume-role trust policies
  - Flags overly permissive roles (e.g., `AdministratorAccess`, `PowerUserAccess`)
- 🌐 **Checks VPC security groups**:
  - Warns on inbound rules (unusual for CodeBuild)
  - Detects overly permissive egress (e.g., `0.0.0.0/0` all ports)
- 📊 **Summarized report** with project issues and runner identification

---

## 📦 Requirements
- Python 3.7+
- [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)  
- AWS credentials configured (via AWS CLI, environment variables, or IAM role)

Install dependencies:
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

## Output Example
![Sample Output](https://github.com/guyHavia/codebuild-sa/blob/788e787ed4fb64905cd507a4bc47c8f311d010a1/images/output_example.png)
