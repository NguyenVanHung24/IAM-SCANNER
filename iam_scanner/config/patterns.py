"""
Privilege Escalation Patterns

Auto-generated from privilege_escalation_paths.csv
Source: DataDog pathfinding.cloud repository

Each pattern defines a set of required AWS IAM permissions that together
enable privilege escalation attacks.
"""

PRIVESC_PATTERNS = {
    # apprunner-001
    "iam:PassRole + apprunner:CreateService": {
        "required": ["iam:PassRole", "apprunner:CreateService"],
        "category": "new-passrole",
        "services": ["iam", "apprunner"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole` and `apprunner:CreateService` can create an AWS App Runner service with a privileged IAM role attached. The service r...",
        "path_id": "apprunner-001"
    },

    # apprunner-002
    "apprunner:UpdateService": {
        "required": ["apprunner:UpdateService"],
        "category": "existing-passrole",
        "services": ["apprunner"],
        "severity": "HIGH",
        "description": "A principal with `apprunner:UpdateService` can modify an existing App Runner service's configuration. If the target service has a privileged IAM role...",
        "path_id": "apprunner-002"
    },

    # bedrock-001
    "iam:PassRole + bedrock-agentcore:CreateCodeInterpreter + bedrock-agentcore:StartCodeInterpreterSession + bedrock-agentcore:InvokeCodeInterpreter": {
        "required": ["iam:PassRole", "bedrock-agentcore:CreateCodeInterpreter", "bedrock-agentcore:StartCodeInterpreterSession", "bedrock-agentcore:InvokeCodeInterpreter"],
        "category": "new-passrole",
        "services": ["iam", "bedrock-agentcore"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole`, `bedrock-agentcore:CreateCodeInterpreter`, `bedrock-agentcore:StartCodeInterpreterSession`, and `bedrock-agentcore:I...",
        "path_id": "bedrock-001"
    },

    # bedrock-002
    "bedrock-agentcore:StartCodeInterpreterSession + bedrock-agentcore:InvokeCodeInterpreter": {
        "required": ["bedrock-agentcore:StartCodeInterpreterSession", "bedrock-agentcore:InvokeCodeInterpreter"],
        "category": "existing-passrole",
        "services": ["bedrock-agentcore"],
        "severity": "HIGH",
        "description": "A principal with `bedrock-agentcore:StartCodeInterpreterSession` and `bedrock-agentcore:InvokeCodeInterpreter` can access an existing Bedrock AgentCor...",
        "path_id": "bedrock-002"
    },

    # cloudformation-001
    "iam:PassRole + cloudformation:CreateStack": {
        "required": ["iam:PassRole", "cloudformation:CreateStack"],
        "category": "new-passrole",
        "services": ["iam", "cloudformation"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole` and `cloudformation:CreateStack` can launch a CloudFormation template that creates AWS resources. The template execu...",
        "path_id": "cloudformation-001"
    },

    # cloudformation-002
    "cloudformation:UpdateStack": {
        "required": ["cloudformation:UpdateStack"],
        "category": "existing-passrole",
        "services": ["cloudformation", "iam"],
        "severity": "HIGH",
        "description": "A principal with `cloudformation:UpdateStack` can modify an existing CloudFormation stack that has an administrative service role attached. CloudForm...",
        "path_id": "cloudformation-002"
    },

    # cloudformation-003
    "iam:PassRole + cloudformation:CreateStackSet + cloudformation:CreateStackInstances": {
        "required": ["iam:PassRole", "cloudformation:CreateStackSet", "cloudformation:CreateStackInstances"],
        "category": "new-passrole",
        "services": ["iam", "cloudformation"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole`, `cloudformation:CreateStackSet`, and `cloudformation:CreateStackInstances` can escalate privileges by creating a Cl...",
        "path_id": "cloudformation-003"
    },

    # cloudformation-004
    "iam:PassRole + cloudformation:UpdateStackSet": {
        "required": ["iam:PassRole", "cloudformation:UpdateStackSet"],
        "category": "new-passrole",
        "services": ["iam", "cloudformation"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole` and `cloudformation:UpdateStackSet` can escalate privileges by modifying an existing CloudFormation StackSet that ha...",
        "path_id": "cloudformation-004"
    },

    # cloudformation-005
    "cloudformation:CreateChangeSet + cloudformation:ExecuteChangeSet": {
        "required": ["cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet"],
        "category": "new-passrole",
        "services": ["cloudformation", "iam"],
        "severity": "HIGH",
        "description": "A principal with `cloudformation:CreateChangeSet` and `cloudformation:ExecuteChangeSet` permissions can inherit administrative privileges from an ex...",
        "path_id": "cloudformation-005"
    },

    # codebuild-001
    "iam:PassRole + codebuild:CreateProject + codebuild:StartBuild": {
        "required": ["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"],
        "category": "new-passrole",
        "services": ["iam", "codebuild"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole`, `codebuild:CreateProject`, and `codebuild:StartBuild` can create a new CodeBuild project and attach an existing pri...",
        "path_id": "codebuild-001"
    },

    # codebuild-002
    "codebuild:StartBuild": {
        "required": ["codebuild:StartBuild"],
        "category": "existing-passrole",
        "services": ["codebuild", "iam"],
        "severity": "HIGH",
        "description": "A principal with `codebuild:StartBuild` can exploit an existing CodeBuild project that has a privileged service role by using the `--buildspec-overri...",
        "path_id": "codebuild-002"
    },

    # codebuild-003
    "codebuild:StartBuildBatch": {
        "required": ["codebuild:StartBuildBatch"],
        "category": "existing-passrole",
        "services": ["codebuild", "iam"],
        "severity": "HIGH",
        "description": "A principal with `codebuild:StartBuildBatch` can exploit an existing CodeBuild project that has a privileged service role by using the `--buildspec-o...",
        "path_id": "codebuild-003"
    },

    # codebuild-004
    "iam:PassRole + codebuild:CreateProject + codebuild:StartBuildBatch": {
        "required": ["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuildBatch"],
        "category": "new-passrole",
        "services": ["iam", "codebuild"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole`, `codebuild:CreateProject`, and `codebuild:StartBuildBatch` can create a new CodeBuild project configured for batch ...",
        "path_id": "codebuild-004"
    },

    # datapipeline-001
    "iam:PassRole + datapipeline:CreatePipeline + datapipeline:PutPipelineDefinition + datapipeline:ActivatePipeline": {
        "required": ["iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition", "datapipeline:ActivatePipeline"],
        "category": "new-passrole",
        "services": ["iam", "datapipeline"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole`, `datapipeline:CreatePipeline`, `datapipeline:PutPipelineDefinition`, and `datapipeline:ActivatePipeline` can create ...",
        "path_id": "datapipeline-001"
    },

    # ec2-001
    "iam:PassRole + ec2:RunInstances": {
        "required": ["iam:PassRole", "ec2:RunInstances"],
        "category": "new-passrole",
        "services": ["iam", "ec2"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole` and `ec2:RunInstances` permissions can launch a new EC2 instance and attach an existing IAM Role to it. By accessing ...",
        "path_id": "ec2-001"
    },

    # ec2-002
    "ec2:ModifyInstanceAttribute + ec2:StopInstances + ec2:StartInstances": {
        "required": ["ec2:ModifyInstanceAttribute", "ec2:StopInstances", "ec2:StartInstances"],
        "category": "existing-passrole",
        "services": ["ec2"],
        "severity": "HIGH",
        "description": "An attacker with the permissions to modify an EC2 instance's attributes, stop it, and start it can gain full control over the instance. The `ec2:Mod...",
        "path_id": "ec2-002"
    },

    # ec2-003
    "iam:PassRole + ec2:RequestSpotInstances": {
        "required": ["iam:PassRole", "ec2:RequestSpotInstances"],
        "category": "new-passrole",
        "services": ["iam", "ec2"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole` and `ec2:RequestSpotInstances` permissions can escalate privileges by requesting an EC2 Spot Instance with a privileg...",
        "path_id": "ec2-003"
    },

    # ec2-004
    "ec2:CreateLaunchTemplateVersion + ec2:ModifyLaunchTemplate": {
        "required": ["ec2:CreateLaunchTemplateVersion", "ec2:ModifyLaunchTemplate"],
        "category": "existing-passrole",
        "services": ["ec2", "iam"],
        "severity": "HIGH",
        "description": "A principal with `ec2:CreateLaunchTemplateVersion` and `ec2:ModifyLaunchTemplate` permissions can escalate privileges by modifying an existing launc...",
        "path_id": "ec2-004"
    },

    # ec2instanceconnect-003
    "ec2-instance-connect:SendSSHPublicKey": {
        "required": ["ec2-instance-connect:SendSSHPublicKey", "ec2:DescribeInstances"],
        "category": "existing-passrole",
        "services": ["ec2", "ec2-instance-connect"],
        "severity": "HIGH",
        "description": "A principal with `ec2-instance-connect:SendSSHPublicKey` can push a temporary SSH public key to an EC2 instance and establish an SSH connection. If t...",
        "path_id": "ec2instanceconnect-003"
    },

    # ecs-001
    "iam:PassRole + ecs:CreateCluster + ecs:RegisterTaskDefinition + ecs:CreateService": {
        "required": ["iam:PassRole", "ecs:CreateCluster", "ecs:RegisterTaskDefinition", "ecs:CreateService"],
        "category": "new-passrole",
        "services": ["iam", "ecs"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole`, `ecs:CreateCluster`, `ecs:RegisterTaskDefinition`, and `ecs:CreateService` can escalate privileges by creating a ne...",
        "path_id": "ecs-001"
    },

    # ecs-002
    "iam:PassRole + ecs:CreateCluster + ecs:RegisterTaskDefinition + ecs:RunTask": {
        "required": ["iam:PassRole", "ecs:CreateCluster", "ecs:RegisterTaskDefinition", "ecs:RunTask"],
        "category": "new-passrole",
        "services": ["iam", "ecs"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole`, `ecs:CreateCluster`, `ecs:RegisterTaskDefinition`, and `ecs:RunTask` can achieve privilege escalation by creating a...",
        "path_id": "ecs-002"
    },

    # ecs-003
    "iam:PassRole + ecs:RegisterTaskDefinition + ecs:CreateService": {
        "required": ["iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:CreateService"],
        "category": "new-passrole",
        "services": ["iam", "ecs"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole`, `ecs:RegisterTaskDefinition`, and `ecs:CreateService` can create an ECS task definition with a privileged IAM role ...",
        "path_id": "ecs-003"
    },

    # ecs-004
    "iam:PassRole + ecs:RegisterTaskDefinition + ecs:RunTask": {
        "required": ["iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"],
        "category": "new-passrole",
        "services": ["iam", "ecs"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole`, `ecs:RegisterTaskDefinition`, and `ecs:RunTask` can create a new ECS task definition and attach an existing IAM rol...",
        "path_id": "ecs-004"
    },

    # ecs-005
    "iam:PassRole + ecs:RegisterTaskDefinition + ecs:StartTask": {
        "required": ["iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:StartTask"],
        "category": "new-passrole",
        "services": ["iam", "ecs"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole`, `ecs:RegisterTaskDefinition`, and `ecs:StartTask` can create a new ECS task definition and attach an existing privi...",
        "path_id": "ecs-005"
    },

    # glue-001
    "iam:PassRole + glue:CreateDevEndpoint": {
        "required": ["iam:PassRole", "glue:CreateDevEndpoint"],
        "category": "new-passrole",
        "services": ["iam", "glue"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole` and `glue:CreateDevEndpoint` can create a new Glue development endpoint and attach an existing privileged IAM role to...",
        "path_id": "glue-001"
    },

    # glue-002
    "glue:UpdateDevEndpoint": {
        "required": ["glue:UpdateDevEndpoint"],
        "category": "existing-passrole",
        "services": ["glue"],
        "severity": "HIGH",
        "description": "A principal with `glue:UpdateDevEndpoint` can modify an existing Glue development endpoint's configuration. If the endpoint has a privileged IAM role...",
        "path_id": "glue-002"
    },

    # iam-001
    "iam:CreatePolicyVersion": {
        "required": ["iam:CreatePolicyVersion"],
        "category": "self-escalation",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:CreatePolicyVersion` permission can modify customer-managed IAM policies by creating a new policy version and setting it as the...",
        "path_id": "iam-001"
    },

    # iam-002
    "iam:SetDefaultPolicyVersion": {
        "required": ["iam:SetDefaultPolicyVersion"],
        "category": "self-escalation",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:SetDefaultPolicyVersion` can change which version of an IAM policy is active. If a customer-managed policy has an existing vers...",
        "path_id": "iam-002"
    },

    # iam-003
    "iam:CreatePolicyVersion + iam:SetDefaultPolicyVersion": {
        "required": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
        "category": "self-escalation",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with both `iam:CreatePolicyVersion` and `iam:SetDefaultPolicyVersion` can modify customer-managed IAM policies in a two-step process. Fir...",
        "path_id": "iam-003"
    },

    # iam-004
    "iam:CreateAccessKey": {
        "required": ["iam:CreateAccessKey"],
        "category": "principal-access",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:CreateAccessKey` can create new access keys for any user, including administrators. This allows the attacker to authenticate as...",
        "path_id": "iam-004"
    },

    # iam-005
    "iam:CreateLoginProfile": {
        "required": ["iam:CreateLoginProfile"],
        "category": "principal-access",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:CreateLoginProfile` can create console access credentials for IAM users that don't already have console access. This allows the...",
        "path_id": "iam-005"
    },

    # iam-006
    "iam:UpdateLoginProfile": {
        "required": ["iam:UpdateLoginProfile"],
        "category": "principal-access",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:UpdateLoginProfile` can change the console password for any IAM user. This allows the attacker to authenticate as that user via...",
        "path_id": "iam-006"
    },

    # iam-007
    "iam:AttachUserPolicy": {
        "required": ["iam:AttachUserPolicy"],
        "category": "self-escalation",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:AttachUserPolicy` can attach AWS managed policies (including AdministratorAccess) or customer-managed policies to any user, inc...",
        "path_id": "iam-007"
    },

    # iam-008
    "iam:AttachGroupPolicy": {
        "required": ["iam:AttachGroupPolicy"],
        "category": "self-escalation",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:AttachGroupPolicy` can attach AWS managed policies (including AdministratorAccess) or customer-managed policies to groups. If t...",
        "path_id": "iam-008"
    },

    # iam-009
    "iam:AttachRolePolicy": {
        "required": ["iam:AttachRolePolicy"],
        "category": "self-escalation",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:AttachRolePolicy` can attach AWS managed policies (including AdministratorAccess) or customer-managed policies to IAM roles. If...",
        "path_id": "iam-009"
    },

    # iam-010
    "iam:PutUserPolicy": {
        "required": ["iam:PutUserPolicy"],
        "category": "self-escalation",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:PutUserPolicy` can create or update inline policies on any IAM user, including themselves. Unlike managed policies which are st...",
        "path_id": "iam-010"
    },

    # iam-011
    "iam:PutGroupPolicy": {
        "required": ["iam:PutGroupPolicy"],
        "category": "self-escalation",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:PutGroupPolicy` can create or update inline policies on any IAM group. If the attacker is a member of the target group (or can ...",
        "path_id": "iam-011"
    },

    # iam-012
    "iam:PutRolePolicy": {
        "required": ["iam:PutRolePolicy"],
        "category": "principal-access",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:PutRolePolicy` can create or update inline policies on any IAM role. By adding a policy with administrative permissions to a ro...",
        "path_id": "iam-012"
    },

    # iam-013
    "iam:AddUserToGroup": {
        "required": ["iam:AddUserToGroup"],
        "category": "principal-access",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:AddUserToGroup` can add any IAM user (including themselves) to any group. If privileged groups exist (such as an \"Administrators...",
        "path_id": "iam-013"
    },

    # iam-014
    "iam:UpdateAssumeRolePolicy": {
        "required": ["iam:UpdateAssumeRolePolicy"],
        "category": "principal-access",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:UpdateAssumeRolePolicy` can modify the trust policy (AssumeRolePolicyDocument) of any IAM role. By adding themselves (their use...",
        "path_id": "iam-014"
    },

    # iam-015
    "iam:CreateUser + iam:CreateAccessKey": {
        "required": ["iam:CreateUser", "iam:CreateAccessKey"],
        "category": "principal-access",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:CreateUser` and `iam:CreateAccessKey` can create a new IAM user and generate access keys for that user. While the new user star...",
        "path_id": "iam-015"
    },

    # iam-016
    "iam:CreateUser + iam:AddUserToGroup": {
        "required": ["iam:CreateUser", "iam:AddUserToGroup"],
        "category": "principal-access",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:CreateUser` and `iam:AddUserToGroup` can create a new IAM user and add them to privileged groups. By adding the new user to an ...",
        "path_id": "iam-016"
    },

    # iam-017
    "iam:CreateUser + iam:AttachUserPolicy": {
        "required": ["iam:CreateUser", "iam:AttachUserPolicy"],
        "category": "principal-access",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:CreateUser` and `iam:AttachUserPolicy` can create a new IAM user and attach AWS managed policies (including AdministratorAccess...",
        "path_id": "iam-017"
    },

    # iam-018
    "iam:CreateUser + iam:PutUserPolicy": {
        "required": ["iam:CreateUser", "iam:PutUserPolicy"],
        "category": "principal-access",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:CreateUser` and `iam:PutUserPolicy` can create a new IAM user and attach an inline policy with administrative permissions. Whil...",
        "path_id": "iam-018"
    },

    # iam-019
    "iam:AttachRolePolicy + iam:UpdateAssumeRolePolicy": {
        "required": ["iam:AttachRolePolicy", "iam:UpdateAssumeRolePolicy"],
        "category": "principal-access",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:AttachRolePolicy` and `iam:UpdateAssumeRolePolicy` can achieve privilege escalation by modifying an existing IAM role. The attac...",
        "path_id": "iam-019"
    },

    # iam-020
    "iam:CreatePolicyVersion + iam:UpdateAssumeRolePolicy": {
        "required": ["iam:CreatePolicyVersion", "iam:UpdateAssumeRolePolicy"],
        "category": "principal-access",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "This is a variation of `iam:CreatePolicyVersion` (iam-001). This variation is needed when you have `iam:CreatePolicyVersion` permission on a customer-...",
        "path_id": "iam-020"
    },

    # iam-021
    "iam:PutRolePolicy + iam:UpdateAssumeRolePolicy": {
        "required": ["iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"],
        "category": "principal-access",
        "services": ["iam"],
        "severity": "CRITICAL",
        "description": "A principal with `iam:PutRolePolicy` and `iam:UpdateAssumeRolePolicy` can achieve privilege escalation by first adding an inline policy with administr...",
        "path_id": "iam-021"
    },

    # lambda-001
    "iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction": {
        "required": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        "category": "new-passrole",
        "services": ["iam", "lambda"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole`, `lambda:CreateFunction`, and `lambda:InvokeFunction` can create a new Lambda function and attach an existing IAM Role...",
        "path_id": "lambda-001"
    },

    # lambda-002
    "iam:PassRole + lambda:CreateFunction + lambda:CreateEventSourceMapping": {
        "required": ["iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"],
        "category": "new-passrole",
        "services": ["iam", "lambda"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole`, `lambda:CreateFunction`, and `lambda:CreateEventSourceMapping` can create a Lambda function with a privileged role an...",
        "path_id": "lambda-002"
    },

    # lambda-003
    "lambda:UpdateFunctionCode": {
        "required": ["lambda:UpdateFunctionCode"],
        "category": "existing-passrole",
        "services": ["lambda"],
        "severity": "HIGH",
        "description": "A principal with `lambda:UpdateFunctionCode` can modify the code of an existing Lambda function that has a privileged execution role. By replacing the...",
        "path_id": "lambda-003"
    },

    # lambda-004
    "lambda:UpdateFunctionCode + lambda:InvokeFunction": {
        "required": ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"],
        "category": "existing-passrole",
        "services": ["lambda"],
        "severity": "HIGH",
        "description": "A principal with `lambda:UpdateFunctionCode` and `lambda:InvokeFunction` can modify the code of an existing Lambda function that has a privileged exec...",
        "path_id": "lambda-004"
    },

    # lambda-005
    "lambda:UpdateFunctionCode + lambda:AddPermission": {
        "required": ["lambda:UpdateFunctionCode", "lambda:AddPermission"],
        "category": "existing-passrole",
        "services": ["lambda"],
        "severity": "HIGH",
        "description": "A principal with `lambda:UpdateFunctionCode` and `lambda:AddPermission` can modify an existing Lambda function's code with malicious code and grant th...",
        "path_id": "lambda-005"
    },

    # lambda-006
    "iam:PassRole + lambda:CreateFunction + lambda:AddPermission": {
        "required": ["iam:PassRole", "lambda:CreateFunction", "lambda:AddPermission"],
        "category": "new-passrole",
        "services": ["iam", "lambda"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole`, `lambda:CreateFunction`, and `lambda:AddPermission` can create a new Lambda function with a privileged execution role...",
        "path_id": "lambda-006"
    },

    # sagemaker-001
    "iam:PassRole + sagemaker:CreateNotebookInstance": {
        "required": ["iam:PassRole", "sagemaker:CreateNotebookInstance"],
        "category": "new-passrole",
        "services": ["iam", "sagemaker"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole` and `sagemaker:CreateNotebookInstance` can create a SageMaker notebook instance with a privileged execution role. Sage...",
        "path_id": "sagemaker-001"
    },

    # sagemaker-002
    "iam:PassRole + sagemaker:CreateTrainingJob": {
        "required": ["iam:PassRole", "sagemaker:CreateTrainingJob"],
        "category": "new-passrole",
        "services": ["iam", "sagemaker"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole` and `sagemaker:CreateTrainingJob` can create a SageMaker training job with a privileged execution role. Training jobs ...",
        "path_id": "sagemaker-002"
    },

    # sagemaker-003
    "iam:PassRole + sagemaker:CreateProcessingJob": {
        "required": ["iam:PassRole", "sagemaker:CreateProcessingJob"],
        "category": "new-passrole",
        "services": ["iam", "sagemaker"],
        "severity": "HIGH",
        "description": "A principal with `iam:PassRole` and `sagemaker:CreateProcessingJob` can create a SageMaker processing job with a privileged execution role. Processing...",
        "path_id": "sagemaker-003"
    },

    # sagemaker-004
    "sagemaker:CreatePresignedNotebookInstanceUrl": {
        "required": ["sagemaker:CreatePresignedNotebookInstanceUrl"],
        "category": "existing-passrole",
        "services": ["sagemaker"],
        "severity": "HIGH",
        "description": "A principal with `sagemaker:CreatePresignedNotebookInstanceUrl` can generate a presigned URL to access an existing SageMaker notebook instance. If the...",
        "path_id": "sagemaker-004"
    },

    # sagemaker-005
    "sagemaker:CreateNotebookInstanceLifecycleConfig + sagemaker:StopNotebookInstance + sagemaker:UpdateNotebookInstance + sagemaker:StartNotebookInstance": {
        "required": ["sagemaker:CreateNotebookInstanceLifecycleConfig", "sagemaker:StopNotebookInstance", "sagemaker:UpdateNotebookInstance", "sagemaker:StartNotebookInstance"],
        "category": "existing-passrole",
        "services": ["sagemaker", "iam"],
        "severity": "HIGH",
        "description": "A principal with SageMaker notebook management permissions can inject malicious code into an existing notebook instance by creating a malicious lifecy...",
        "path_id": "sagemaker-005"
    },

    # ssm-001
    "ssm:StartSession": {
        "required": ["ssm:StartSession"],
        "category": "existing-passrole",
        "services": ["ssm", "ec2"],
        "severity": "HIGH",
        "description": "The `ssm:StartSession` permission allows a principal to remotely access any EC2 instance on which they have this permission. This access is contingent...",
        "path_id": "ssm-001"
    },

    # ssm-002
    "ssm:SendCommand": {
        "required": ["ssm:SendCommand"],
        "category": "existing-passrole",
        "services": ["ssm", "ec2"],
        "severity": "HIGH",
        "description": "The `ssm:SendCommand` permission allows a principal to execute commands on any EC2 instance on which they have this permission, using SSM Run Command....",
        "path_id": "ssm-002"
    },

    # sts-001
    "sts:AssumeRole": {
        "required": ["sts:AssumeRole"],
        "category": "principal-access",
        "services": ["sts"],
        "severity": "CRITICAL",
        "description": "A principal with `sts:AssumeRole` permission can assume IAM roles that trust them in their trust policy. We refer to this as two-way trust, or bidirec...",
        "path_id": "sts-001"
    }

}
