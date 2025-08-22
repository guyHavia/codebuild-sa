"""
AWS CodeBuild Security Audit Script

This script analyzes CodeBuild projects for potential security issues:
- Checks webhook event filtering and branch protection
- Validates IAM role assume policies and attached permissions
- Reviews security group configurations

Requirements:
- boto3
- AWS credentials configured (via AWS CLI, environment variables, or IAM role)
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from typing import Dict, List, Any, Optional
import sys

class CodeBuildSecurityAuditor:
    def __init__(self):
        try:
            self.codebuild = boto3.client('codebuild')
            self.iam = boto3.client('iam')
            self.ec2 = boto3.client('ec2')
            self.sts = boto3.client('sts')
            
            # Get current account ID
            self.account_id = self.sts.get_caller_identity()['Account']

            
        except NoCredentialsError:
            print("❌ Error: AWS credentials not found. Please configure AWS credentials.")
            raise
        except Exception as e:
            print(f"❌ Error initializing AWS clients: {str(e)}")
            raise

    def get_all_codebuild_projects(self) -> List[str]:
        """Get all CodeBuild project names in the account"""
        try:
            projects = []
            paginator = self.codebuild.get_paginator('list_projects')
            
            for page in paginator.paginate():
                projects.extend(page['projects'])
            
            print(f"Found {len(projects)} CodeBuild projects")
            return projects
            
        except ClientError as e:
            print(f"❌ Error listing CodeBuild projects: {str(e)}")
            return []

    def is_runner_project(self, project_details: Dict) -> bool:
        """
        Determine if a project is a runner project based on naming patterns and configuration
        Common patterns: contains 'runner', 'github-runner', 'self-hosted', etc.
        """
        project_name = project_details.get('name', '').lower()
        description = project_details.get('description', '').lower()
        
        runner_indicators = [
            'runner', 'github-runner', 'self-hosted', 'actions-runner',
            'gitlab-runner', 'ci-runner', 'build-runner'
        ]
        
        # Check name and description for runner indicators
        for indicator in runner_indicators:
            if indicator in project_name or indicator in description:
                return True
        
        # Check if it has webhook configuration (common for runners)
        webhook = project_details.get('webhook', {})
        if webhook and webhook.get('payloadUrl'):
            return True
            
        return False

    def check_webhook_filtering(self, project_details: Dict) -> Dict[str, Any]:
        """Check webhook event filtering and branch protection"""
        webhook_info = {
            'has_webhook': False,
            'branch_protection_missing': False,
            'filter_groups': [],
            'issues': []
        }
        
        webhook = project_details.get('webhook', {})
        if not webhook:
            return webhook_info
            
        webhook_info['has_webhook'] = True
        filter_groups = webhook.get('filterGroups', [])
        webhook_info['filter_groups'] = filter_groups
        
        if not filter_groups:
            webhook_info['branch_protection_missing'] = True
            webhook_info['issues'].append("No webhook filter groups defined - all events will trigger builds")
            return webhook_info
        
        # Check each filter group - ALL groups must have branch protection since they use OR logic
        unprotected_groups = []
        protected_groups = []
        
        for group_idx, group in enumerate(filter_groups):
            group_has_branch_protection = False
            group_has_event_filter = False
            
            for filter_item in group:
                filter_type = filter_item.get('type')
                pattern = filter_item.get('pattern', '')
                
                # Check for branch protection (HEAD_REF or BASE_REF)
                if filter_type in ['HEAD_REF', 'BASE_REF']:
                    if pattern and ('main' in pattern or 'master' in pattern or 'refs/heads/' in pattern):
                        group_has_branch_protection = True
                
                # Check for event filters
                if filter_type == 'EVENT':
                    group_has_event_filter = True
            
            # A group is considered protected if it has branch protection OR is very specific about events
            # Events that are generally safe without branch protection
            safe_events_without_branch = ['PULL_REQUEST_CREATED', 'PULL_REQUEST_UPDATED', 'PULL_REQUEST_REOPENED']
            
            group_info = {
                'group_index': group_idx,
                'filters': group,
                'has_branch_protection': group_has_branch_protection,
                'has_event_filter': group_has_event_filter
            }
            
            if group_has_branch_protection:
                protected_groups.append(group_info)
            else:
                # Check if the group has only safe events
                group_events = [f.get('pattern') for f in group if f.get('type') == 'EVENT']
                if group_events and all(event in safe_events_without_branch for event in group_events):
                    # This is acceptable - PR events without branch filters are generally safe
                    protected_groups.append(group_info)
                else:
                    unprotected_groups.append(group_info)
        
        if unprotected_groups:
            webhook_info['branch_protection_missing'] = True
            for group in unprotected_groups:
                group_idx = group['group_index']
                events = [f.get('pattern', 'UNKNOWN') for f in group['filters'] if f.get('type') == 'EVENT']
                if events:
                    webhook_info['issues'].append(
                        f"Filter group {group_idx} allows unrestricted access via events: {events} (no branch protection)"
                    )
                else:
                    webhook_info['issues'].append(
                        f"Filter group {group_idx} has no branch protection and unclear event filtering"
                    )
        
        # Additional check: if there are multiple groups and any are unprotected, flag it
        if len(filter_groups) > 1 and unprotected_groups:
            webhook_info['issues'].append(
                f"Multiple filter groups detected with OR logic - {len(unprotected_groups)} unprotected group(s) can bypass protected groups"
            )
            
            # Specific case: protected + permissive groups combination
            if protected_groups and unprotected_groups:
                critical_issue = (
                    f"CRITICAL: Webhook has {len(protected_groups)} protected filter group(s) AND "
                    f"{len(unprotected_groups)} permissive group(s). The permissive groups completely "
                    f"bypass branch protection due to OR logic between filter groups!"
                )
                webhook_info['issues'].append(critical_issue)
                # This will be printed when the issue is processed in audit_project
        
        return webhook_info

    def check_iam_role_security(self, role_arn: str) -> Dict[str, Any]:
        """Check IAM role for security issues"""
        role_info = {
            'role_name': role_arn.split('/')[-1],
            'assume_policy_issues': [],
            'has_admin_access': False,
            'managed_policies': [],
            'inline_policies': []
        }
        
        try:
            role_name = role_arn.split('/')[-1]
            
            # Check assume role policy
            role_details = self.iam.get_role(RoleName=role_name)
            assume_policy = role_details['Role']['AssumeRolePolicyDocument']
            
            for statement in assume_policy.get('Statement', []):
                principals = statement.get('Principal', {})
                if isinstance(principals, dict):
                    service_principals = principals.get('Service', [])
                    if isinstance(service_principals, str):
                        service_principals = [service_principals]
                    
                    non_codebuild_services = [s for s in service_principals if s != 'codebuild.amazonaws.com']
                    if non_codebuild_services:
                        role_info['assume_policy_issues'].extend(non_codebuild_services)
            
            # Check attached managed policies
            managed_policies = self.iam.list_attached_role_policies(RoleName=role_name)
            for policy in managed_policies['AttachedPolicies']:
                policy_name = policy['PolicyName']
                role_info['managed_policies'].append(policy_name)
                
                if policy_name.lower() in ['administratoraccess', 'poweruseraccess']:
                    role_info['has_admin_access'] = True
            
            # Check inline policies
            inline_policies = self.iam.list_role_policies(RoleName=role_name)
            role_info['inline_policies'] = inline_policies['PolicyNames']
            
        except ClientError as e:
            role_info['error'] = f"Error checking IAM role: {str(e)}"
        
        return role_info

    def check_security_groups(self, vpc_config: Dict) -> Dict[str, Any]:
        """Check security groups for overly permissive rules"""
        sg_info = {
            'security_groups': [],
            'issues': []
        }
        
        if not vpc_config or not vpc_config.get('securityGroupIds'):
            return sg_info
        
        try:
            sg_ids = vpc_config['securityGroupIds']
            response = self.ec2.describe_security_groups(GroupIds=sg_ids)
            
            for sg in response['SecurityGroups']:
                sg_details = {
                    'group_id': sg['GroupId'],
                    'group_name': sg['GroupName'],
                    'issues': []
                }
                
                # Check egress rules
                for rule in sg.get('IpPermissionsEgress', []):
                    port = rule.get('FromPort')
                    protocol = rule.get('IpProtocol')
                    
                    # Check if it's not just HTTPS (443) egress
                    if not (port == 443 and protocol == 'tcp'):
                        if protocol == '-1':  # All traffic
                            sg_details['issues'].append("Allows all outbound traffic")
                        elif port != 443:
                            sg_details['issues'].append(f"Allows outbound traffic on port {port}/{protocol}")
                
                # Check ingress rules (should typically be empty for CodeBuild)
                if sg.get('IpPermissions'):
                    sg_details['issues'].append("Has inbound rules (unusual for CodeBuild)")
                
                sg_info['security_groups'].append(sg_details)
                if sg_details['issues']:
                    sg_info['issues'].extend([f"SG {sg['GroupId']}: {issue}" for issue in sg_details['issues']])
        
        except ClientError as e:
            sg_info['error'] = f"Error checking security groups: {str(e)}"
        
        return sg_info

    def audit_project(self, project_name: str) -> Dict[str, Any]:
        """Perform comprehensive security audit on a single project"""
        try:
            # Get project details
            response = self.codebuild.batch_get_projects(names=[project_name])
            if not response['projects']:
                return {'error': f'Project {project_name} not found'}
            
            project = response['projects'][0]
                        
            audit_result = {
                'project_name': project_name,
                'is_runner': self.is_runner_project(project),
                'service_role': project.get('serviceRole'),
                'issues': []
            }
            
            # Check if it's a runner project
            if audit_result['is_runner']:
                
                # Check webhook filtering
                webhook_info = self.check_webhook_filtering(project)
                audit_result['webhook_info'] = webhook_info
                
                if webhook_info['branch_protection_missing']:
                    # Add the generic message
                    generic_issue = "❌ Runner project lacks proper branch protection in webhook filters"
                    audit_result['issues'].append(generic_issue)
                    
                    # Add specific detailed issues
                    for specific_issue in webhook_info['issues']:
                        detailed_issue = f"❌ {specific_issue}"
                        audit_result['issues'].append(detailed_issue)
            
            # Check IAM role
            if audit_result['service_role']:
                iam_info = self.check_iam_role_security(audit_result['service_role'])
                audit_result['iam_info'] = iam_info
                
                if iam_info['assume_policy_issues']:
                    issue = f"❌ Role can be assumed by services other than CodeBuild: {iam_info['assume_policy_issues']}"
                    audit_result['issues'].append(issue)
                
                if iam_info['has_admin_access']:
                    issue = "❌ Role has AdministratorAccess or PowerUserAccess policy"
                    audit_result['issues'].append(issue)
            
            # Check security groups
            vpc_config = project.get('vpcConfig', {})
            if vpc_config:
                sg_info = self.check_security_groups(vpc_config)
                audit_result['security_group_info'] = sg_info
                
                if sg_info['issues']:
                    for issue in sg_info['issues']:
                        full_issue = f"❌ Security Group Issue: {issue}"
                        audit_result['issues'].append(full_issue)
            
            return audit_result
            
        except ClientError as e:
            return {'project_name': project_name, 'error': f'Error auditing project: {str(e)}'}

    def run_audit(self):
        """Run the complete security audit"""
        
        # Get all projects
        project_names = self.get_all_codebuild_projects()
        if not project_names:
            print("❌ No CodeBuild projects found or unable to list projects")
            return
        
        # Audit each project
        audit_results = []
        issues_found = 0
        
        for project_name in project_names:
            result = self.audit_project(project_name)
            audit_results.append(result)
            issues_found += len(result.get('issues', []))
        
        # Print summary
        print(f"\n" + "="*60)
        print(f"📊 AUDIT SUMMARY")
        print(f"="*60)
        print(f"Total projects audited: {len(project_names)}")
        print(f"Total issues found: {issues_found}")
        
        runner_projects = [r for r in audit_results if r.get('is_runner')]
        if runner_projects:
            print(f"Runner projects identified: {len(runner_projects)}")
            for rp in runner_projects:
                print(f"  - {rp['project_name']}")
        
        # List all issues
        if issues_found > 0:
            print(f"\n🚨 ISSUES SUMMARY:")
            for result in audit_results:
                if result.get('issues'):
                    print(f"\n{result['project_name']}:")
                    for issue in result['issues']:
                        print(f"  {issue}")
        else:
            print(f"\n✅ No security issues found across all projects!")

def audit_oidc_role_trust_policy(role_name):
    """Audit OIDC role trust policy for overly permissive configurations"""
    try:
        iam = boto3.client('iam')
        
        # Get the role
        response = iam.get_role(RoleName=role_name)
        trust_policy = response['Role']['AssumeRolePolicyDocument']
        
        issues = []
        
        # Check each statement in the trust policy
        for statement in trust_policy.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                # Check for AssumeRoleWithWebIdentity action
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                if 'sts:AssumeRoleWithWebIdentity' in actions:
                    conditions = statement.get('Condition', {})
                    string_equals = conditions.get('StringEquals', {})
                    string_like = conditions.get('StringLike', {})
                    
                    # Check for GitHub OIDC conditions
                    github_conditions = {}
                    for key, value in {**string_equals, **string_like}.items():
                        if 'token.actions.githubusercontent.com' in key:
                            github_conditions[key] = value
                    
                    # Analyze the 'sub' claim for overly permissive patterns
                    sub_claim = github_conditions.get('token.actions.githubusercontent.com:sub')
                    if sub_claim:
                        if isinstance(sub_claim, str):
                            sub_claim = [sub_claim]
                        
                        for sub in sub_claim:
                            # Check for org-wide permissions (repo:org/*)
                            if sub.endswith('/*') and sub.count('/') == 1 and ':' in sub:
                                # Pattern: repo:org/* (allows all repos in org)
                                org_name = sub.split(':')[1].split('/')[0] if ':' in sub else 'unknown'
                                issues.append(f"⚠️  Role allows ALL repositories in organization '{org_name}': {sub}")
                            
                            # Check for repo-wide permissions (repo:org/repo/*)
                            elif sub.endswith('/*') and sub.count('/') == 2 and ':' in sub:
                                # Pattern: repo:org/repo/* (allows all branches in specific repo)
                                repo_path = sub.split(':')[1].rstrip('/*') if ':' in sub else 'unknown'
                                issues.append(f"⚠️  Role allows ALL branches in repository '{repo_path}': {sub}")
                            
                            # Check for ref-level permissions (repo:org/repo:*)
                            elif sub.endswith(':*') and sub.count(':') >= 2:
                                repo_path = sub.split(':')[1] if ':' in sub else 'unknown'
                                issues.append(f"⚠️  Role allows ALL branches in repository '{repo_path}': {sub}")
                            
                            # Check for other wildcard patterns that might be too broad
                            elif '*' in sub and not sub.endswith(':ref:refs/heads/main') and not sub.endswith(':ref:refs/heads/master'):
                                issues.append(f"⚠️  Role uses potentially broad wildcard pattern: {sub}")
        
        return issues
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return [f"❌ Role '{role_name}' not found"]
        else:
            return [f"❌ Error accessing role '{role_name}': {str(e)}"]
    except Exception as e:
        return [f"❌ Unexpected error auditing role '{role_name}': {str(e)}"]


def print_oidc_audit_summary(role_name, issues):
    """Print OIDC audit summary in the same format as the main audit"""
    print(f"\n" + "="*60)
    print(f"📊 OIDC ROLE AUDIT SUMMARY")
    print(f"="*60)
    print(f"Role audited: {role_name}")
    print(f"Total issues found: {len(issues)}")
    
    if issues:
        print(f"\n🚨 ISSUES SUMMARY:")
        print(f"\n{role_name}:")
        for issue in issues:
            print(f"  {issue}")
        
        print(f"\n💡 RECOMMENDATIONS:")
        print(f"  • Restrict 'sub' claims to specific repositories and branches")
        print(f"  • Use format: 'repo:org/repo:ref:refs/heads/branch-name'")
        print(f"  • Avoid wildcards (*) unless absolutely necessary")
        print(f"  • Consider separate roles for different repositories/branches")
    else:
        print(f"\n✅ No OIDC trust policy issues found for role '{role_name}'!")

def main():
    """Main function to run the audit"""
    try:
         # Check command line arguments to determine execution mode
        if len(sys.argv) < 2:
            print("❌ Usage: python3 <script_name> <mode> [role_name]")
            print("   Modes: 'runner' - Run CodeBuild security audit")
            print("          'oidc' - Audit OIDC role trust policy (requires role_name)")
            return 1
        
        mode = sys.argv[1].lower()
        
        if mode == "runner":
            auditor = CodeBuildSecurityAuditor()
            auditor.run_audit()

        elif mode == "oidc":
            # OIDC role trust policy audit
            if len(sys.argv) < 3:
                print("❌ OIDC mode requires role name")
                print("Usage: python3 <script_name> oidc <role_name>")
                return 1
            
            role_name = sys.argv[2]
            print(f"🔍 Auditing OIDC role trust policy for: {role_name}")
            
            issues = audit_oidc_role_trust_policy(role_name)
            print_oidc_audit_summary(role_name, issues)
            
        else:
            print(f"❌ Unknown mode: {mode}")
            print("Available modes: 'runner', 'oidc'")
            return 1
        
    except Exception as e:
        print(f"❌ Fatal error: {str(e)}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())