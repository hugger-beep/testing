# AWS Cross-Account Access Control Test Plan

## Test Plan Overview

🔹 **Part 1: Baseline** – Confirm External Access Works  
This phase ensures that your Lambda function is accessible from outside your AWS Organization before any restrictions are applied.

**Steps:**
1. Create a Lambda function in your target AWS account
2. Create an IAM user or role in a different AWS account (outside your org)
3. Give that external principal permission to invoke your Lambda
4. Invoke the Lambda using AWS CLI or SDK from the external account
5. Check CloudTrail logs in the target account to confirm the invocation succeeded and came from outside your org

---

## Step 1: Create Lambda in Target Account

**Create Lambda in Target Account and note the ARN**

Simple Lambda in Target Account:

```python
def lambda_handler(event, context):
    return {
        'statusCode': 200,
        'body': 'Lambda executed successfully!'
    }
```

---

## Step 2: Grant Invoke Permission to Source Account

```bash
aws lambda add-permission \
  --function-name demo-external-access \
  --statement-id AllowSourceAccountInvoke \
  --action lambda:InvokeFunction \
  --principal Account B \
  --region us-west-2 \
  --output json
```

**Check the lambda exists:**
```bash
aws lambda list-functions --query 'Functions[?FunctionName==`demo-external-access`]' --output table

# List all functions to find the correct name
aws lambda list-functions --query 'Functions[].FunctionName' --output table
```

---

## Step 3: Invoke Lambda from Source Account

**Command:**
```bash
aws lambda invoke \
  --function-name arn:aws:lambda:us-west-2:Account A:function:demo-external-access \
  --region us-west-2 \
  response.json
```

**Result:**
```bash
~ $ aws lambda invoke \
>   --function-name arn:aws:lambda:us-west-2:Account A:function:demo-external-access \
>   --region us-west-2 \
>   response.json
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}
```

✅ **Baseline Confirmed:** External access works before restrictions

---

## Step 4: Apply SCP/RCP in Target Account

### SCP Option 1 - Basic Org Restriction  // don't use this policy , use the one below that tries to block AWS lambda and IAM role assumption

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonOrgPrincipals",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-example789012" // Replace with your org ID
        }
      }
    },
    {
      "Sid": "DenyUnapprovedServices",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "ForAllValues:StringNotEquals": {
          "aws:CalledVia": [
            "cloudformation.amazonaws.com",
            "config.amazonaws.com",
            "support.amazonaws.com",
            "trustedadvisor.amazonaws.com",
            "organizations.amazonaws.com"
          ]
        }
      }
    }
  ]
}
```

### SCP Option 2 - Comprehensive Service Control

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonOrgPrincipals",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-example123456" // Replace with your org ID
        }
      }
    },
    {
      "Sid": "DenyUnapprovedCalledViaServices",
      "Effect": "Deny",
      "Action": [
        "ec2:*",
        "s3:*",
        "cloudformation:*",
        "config:*",
        "lambda:InvokeFunction",
        "organizations:*",
        "iam:*",
        "rds:*",
        "dynamodb:*"
      ],
      "Resource": "*",
      "Condition": {
        "ForAllValues:StringNotEquals": {
          "aws:CalledVia": [
            "cloudformation.amazonaws.com",
            "config.amazonaws.com",
            "support.amazonaws.com",
            "trustedadvisor.amazonaws.com",
            "organizations.amazonaws.com",
            "ec2.amazonaws.com",
            "s3.amazonaws.com",
            "cloudshell.amazonaws.com"
          ]
        }
      }
    },
    {
      "Sid": "DenyLambdaInvokeFromOutsideOrg",
      "Effect": "Deny",
      "Action": "lambda:InvokeFunction",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-example123456" // Replace with your org ID
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false"
        }
      }
    },
    {
      "Sid": "DenyAssumeRoleFromOutsideOrg",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-example123456" // Replace with your org ID
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false"
        }
      }
    }
  ]
}
```

### SCP Statement Analysis

| Statement | Purpose | Covers Lambda? | Notes |
|-----------|---------|----------------|-------|
| DenyNonOrgPrincipals | Block all actions from outside org | ✅ Yes | Broad but may miss service-to-service nuances |
| DenyUnapprovedServices | Block actions not via approved services | ⚠️ Maybe | Depends on presence of aws:CalledVia |
| DenyLambdaInvokeFromOutsideOrg | Explicitly block Lambda invocation | ✅ Yes | Adds clarity and precision |
| DenyAssumeRoleFromOutsideOrg | Block role assumption from outside org | ✅ Yes | Critical for cross-account access control |

### 🔍 Why Explicit Deny for Lambda Is Still Useful

**Defense in Depth:** AWS policy evaluation is complex. Adding a specific deny for `lambda:InvokeFunction` ensures that even if other conditions are bypassed or misconfigured, this critical action is still blocked.

**Audit Clarity:** When someone reviews your SCP, they immediately see that Lambda invocation is a sensitive action.

**Policy Evaluation Nuances:** Conditions like `aws:CalledVia` only apply in certain contexts. If a principal directly invokes Lambda, `aws:CalledVia` might not be present—so the second statement might not trigger.

---

## Step 5: Test SCP Effectiveness

**⚠️ Important Discovery:** SCPs don't apply to cross-account resource-based policy access.

When Account B invokes Account A's Lambda via resource policy:
- The resource policy evaluation happens in Account A
- But the SCP only applies to Account A's principals, not Account B's
- Account B is using its own identity with Account A's resource policy permission

### ✅ Correct Understanding:
- SCPs are guardrails for principals within the same organization
- Resource-based policies can grant cross-account access independent of SCPs
- The SCP would block Account A users, but not Account B users accessing via resource policy

**Result:** Lambda invoke still works despite SCP because resource policy overrides SCP restrictions for cross-account access.

---

## Step 6: Apply RCP (Resource Control Policy)

### RCP for Cross-Account Access Control

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyExternalAssumeRole",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "sts:AssumeRole",
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:PrincipalOrgID": "o-example123456" // Replace with your org ID
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false"
        }
      }
    },
    {
      "Sid": "DenyAccessFromOutsideOrg",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "secretsmanager:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-example123456" // Replace with your org ID
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false"
        }
      }
    }
  ]
}
```

### What This RCP Covers

This RCP will apply to resources from the following services:
- Amazon S3
- AWS STS  
- AWS KMS
- Amazon SQS
- AWS Secrets Manager
- Amazon ECR
- Amazon OpenSearch Serverless
- Amazon Cognito User Pools

**⚠️ Note:** This policy does not affect EC2, Lambda, etc., because RCPs don't support those services yet.

### RCP Supported Services
[AWS Documentation - RCP Supported Services](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html#rcp-supported-services)

---

## Policy Comparison Table

| Policy Type | Applies To | Controls | Cross-Account Impact |
|-------------|------------|----------|---------------------|
| SCP | Principals in Org | What actions they can take | Indirect (blocks internal principals only) |
| Resource-Based Policy | Specific resource | Who can access it | Direct (grants access to external accounts) |
| RCP | Specific resource | Who can access it + conditions | Direct (can block external access even if allowed by resource policy) |

---

## Test Case 1: Cross-Org Role Assumption

### ✅ Step 1: Confirm Org Membership
- Ensure Account A is part of AWS Organization o-example123456 // Replace with your org ID
- Ensure Account B is not part of that organization

### ✅ Step 2: Create IAM Role in Account A
In Account A, create a role named `CrossAccountTestRole` with trust policy allowing Account B:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::Account B:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### ✅ Step 3: Attach the RCP in Account A
Attach your RCP to enforce the `DenyExternalAssumeRole` condition.

### 🚀 Step 4: Attempt Role Assumption from Account B

**Before RCP:**
```bash
aws sts assume-role \
  --role-arn arn:aws:iam::Account A:role/CrossAccountTestRole \
  --role-session-name TestSession
```
**Result:** ✅ Pass

**After RCP:**
```bash
aws sts assume-role \
  --role-arn arn:aws:iam::Account A:role/CrossAccountTestRole \
  --role-session-name TestSession
```
**Expected Result:** ❌ AccessDenied error - "An error occurred (AccessDenied) when calling the AssumeRole operation"

---

## Test Case 2: Cross-Org Secrets Manager Access

### Objective
Verify that Account B (outside Org o-example123456) cannot access a secret stored in Account A, even if granted permission via a resource-based policy.

### ✅ Step 1: Confirm Org Membership
- Account A is in Org o-example123456 // Replace with your org ID
- Account B is not in that Org

### ✅ Step 2: Create a Secret in Account A
```bash
aws secretsmanager create-secret \
  --name TestCrossOrgSecret \
  --secret-string '{"username":"admin","password":"123456"}'
```

### ✅ Step 3: Add Resource-Based Policy to the Secret
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAccountBAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::Account B:root"
      },
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "*"
    }
  ]
}
```

### ✅ Step 4a: Attempt Access from Account B (Before RCP)

```bash
aws secretsmanager get-secret-value \
  --secret-id arn:aws:secretsmanager:<region>:Account A:secret:TestCrossOrgSecret
```

**Note:** If using default KMS key you willl get an error, add to the CMK policy instead:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAccountBUse",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::Account B:root"
      },
      "Action": [
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    }
  ]
}
```

**Test Command:**
```bash
aws secretsmanager get-secret-value \
  --secret-id arn:aws:secretsmanager:us-west-2:Account A:secret:ADAdminSecret-5UxiUI
```
**Result:** ✅ Should pass

### ✅ Step 4b: Attach the RCP in Account A

Ensure your RCP is attached and active:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAccessFromOutsideOrg",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-example123456" // Replace with your org ID
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false"
        }
      }
    }
  ]
}
```

### Step 5: Attempt Access from Account B (After RCP)

```bash
aws secretsmanager get-secret-value \
  --secret-id arn:aws:secretsmanager:us-west-2:Account A:secret:ADAdminSecret-5UxiUI
```

**Result:** ❌ **Access Denied**

```
An error occurred (AccessDeniedException) when calling the GetSecretValue operation: User: arn:aws:sts::Account B:assumed-role/admin/username-session is not authorized to perform: secretsmanager:GetSecretValue on resource: arn:aws:secretsmanager:us-west-2:Account A:secret:ADAdminSecret with an explicit deny in a resource control policy
```

---

## Test Results Summary

| Test Case | Before SCP/RCP | After SCP Only | After RCP |
|-----------|----------------|----------------|-----------|
| **Lambda Invoke** | ✅ Pass | ✅ Pass (Resource policy overrides) | ❌ Not supported by RCP |
| **Role Assumption** | ✅ Pass | ✅ Pass (Resource policy overrides) | ❌ Denied by RCP |
| **Secrets Manager** | ✅ Pass | ✅ Pass (Resource policy overrides) | ❌ Denied by RCP |

## Key Findings

### 🔍 SCP Limitations
- **SCPs don't block cross-account resource-based policy access**
- Resource policies can grant access independent of SCPs
- SCPs only apply to principals within the same organization

### ✅ RCP Effectiveness  
- **RCPs successfully block cross-account access** even when resource policies allow it
- RCPs work at the resource level, not the principal level
- **Limited service support** - Lambda not yet supported

### 🎯 Recommendations
1. **Use RCPs for supported services** (S3, Secrets Manager, STS, etc.)
2. **Remove resource policies** for unsupported services like Lambda
3. **Combine both approaches** for comprehensive cross-account access control
4. **Monitor AWS updates** for expanded RCP service support

---

## Conclusion

**RCPs are the most effective way to block cross-account access** for supported services, as they can override resource-based policies. For services not yet supported by RCPs (like Lambda), removing or restricting resource-based policies remains the primary control mechanism.
