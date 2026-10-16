data "aws_region" "current" {}

###################
#### SNS topic ####
###################

resource "aws_sns_topic" "audit" {
  name = "${var.name}-alerts"
  tags = var.tags
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.audit.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

##############################
#### IAM EventBridge rule ####
##############################

resource "aws_cloudwatch_event_rule" "iam_changes" {
  name        = "${var.name}-iam-changes"
  description = "CloudTrail audit alerts for IAM changes"
  is_enabled  = data.aws_region.current.name == "us-east-1"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName = [
        "AddClientIDToOpenIDConnectProvider",
        "AddRoleToInstanceProfile",
        "AddUserToGroup",
        "AttachGroupPolicy",
        "AttachRolePolicy",
        "AttachUserPolicy",
        "ChangePassword",
        "CreateAccessKey",
        "CreateGroup",
        "CreateInstanceProfile",
        "CreateLoginProfile",
        "CreateOpenIDConnectProvider",
        "CreatePolicy",
        "CreatePolicyVersion",
        "CreateRole",
        "CreateSAMLProvider",
        "CreateServiceSpecificCredential",
        "CreateUser",
        "CreateVirtualMFADevice",
        "DeactivateMFADevice",
        "DeleteAccessKey",
        "DeleteAccountPasswordPolicy",
        "DeleteGroup",
        "DeleteGroupPolicy",
        "DeleteInstanceProfile",
        "DeleteLoginProfile",
        "DeleteOpenIDConnectProvider",
        "DeletePolicy",
        "DeletePolicyVersion",
        "DeleteRole",
        "DeleteRolePolicy",
        "DeleteSAMLProvider",
        "DeleteServerCertificate",
        "DeleteServiceSpecificCredential",
        "DeleteSigningCertificate",
        "DeleteSSHPublicKey",
        "DeleteUser",
        "DeleteUserPolicy",
        "DeleteVirtualMFADevice",
        "DetachGroupPolicy",
        "DetachRolePolicy",
        "DetachUserPolicy",
        "EnableMFADevice",
        "PutGroupPolicy",
        "PutRolePolicy",
        "PutUserPolicy",
        "RemoveClientIDFromOpenIDConnectProvider",
        "RemoveRoleFromInstanceProfile",
        "RemoveUserFromGroup",
        "ResetServiceSpecificCredential",
        "ResyncMFADevice",
        "SetDefaultPolicyVersion",
        "SetSecurityTokenServicePreferences",
        "TagOpenIDConnectProvider",
        "TagPolicy",
        "TagRole",
        "TagSAMLProvider",
        "TagServerCertificate",
        "TagUser",
        "UntagOpenIDConnectProvider",
        "UntagPolicy",
        "UntagRole",
        "UntagSAMLProvider",
        "UntagServerCertificate",
        "UntagUser",
        "UpdateAccessKey",
        "UpdateAccountPasswordPolicy",
        "UpdateAssumeRolePolicy",
        "UpdateGroup",
        "UpdateLoginProfile",
        "UpdateOpenIDConnectProviderThumbprint",
        "UpdateRole",
        "UpdateRoleDescription",
        "UpdateSAMLProvider",
        "UpdateServerCertificate",
        "UpdateServiceSpecificCredential",
        "UpdateSigningCertificate",
        "UpdateSSHPublicKey",
        "UpdateUser",
        "UploadServerCertificate",
        "UploadSigningCertificate",
        "UploadSSHPublicKey",
      ]
    }
  })

  tags = var.tags

}

##################################
#### Secret modification rule ####
##################################

resource "aws_cloudwatch_event_rule" "secret_changes" {
  name        = "${var.name}-secret-changes"
  description = "CloudTrail audit alerts for Secrets Manager changes"

  event_pattern = jsonencode({
    source      = ["aws.secretsmanager"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["secretsmanager.amazonaws.com"]
      eventName = [
        "CancelRotateSecret",
        "CreateSecret",
        "DeleteResourcePolicy",
        "DeleteSecret",
        "PutResourcePolicy",
        "PutSecretValue",
        "RemoveRegionsFromReplication",
        "ReplicateSecretToRegions",
        "RestoreSecret",
        "RotateSecret",
        "StopReplicationToReplica",
        "TagResource",
        "UntagResource",
        "UpdateSecret",
        "UpdateSecretVersionStage",
      ]
    }
  })

  tags = var.tags
}

##################################
#### Direct secret reads rule ####
##################################

resource "aws_cloudwatch_event_rule" "secret_reads_direct" {
  name        = "${var.name}-secret-reads-direct"
  description = "CloudTrail audit alerts for direct Secrets Manager reads"

  event_pattern = jsonencode({
    source      = ["aws.secretsmanager"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["secretsmanager.amazonaws.com"]
      eventName = [
        "BatchGetSecretValue",
        "GetSecretValue",
      ]
      userIdentity = {
        type = [
          "FederatedUser",
          "IAMUser",
          "IdentityCenterUser",
          "Root",
        ]
      }
    }
  })

  tags = var.tags
}

########################################
#### Assumed role secret reads rule ####
########################################

resource "aws_cloudwatch_event_rule" "secret_reads_assumed_role" {
  name        = "${var.name}-secret-reads-role"
  description = "CloudTrail audit alerts for Secrets Manager reads through assumed roles"

  event_pattern = jsonencode({
    source      = ["aws.secretsmanager"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["secretsmanager.amazonaws.com"]
      eventName = [
        "BatchGetSecretValue",
        "GetSecretValue",
      ]
      userIdentity = {
        type = ["AssumedRole"]
        sessionContext = {
          sessionIssuer = {
            arn = [{
              anything-but = concat(
                sort(tolist(var.exception_role_arns)),
                ["arn:aws:iam::000000000000:role/terraform-cloudtrail-audit-no-match"],
              )
            }]
          }
        }
      }
    }
  })

  tags = var.tags
}

##########################
#### SNS topic policy ####
##########################

data "aws_iam_policy_document" "sns" {
  statement {
    sid       = "AllowEventBridgePublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.audit.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values = [
        aws_cloudwatch_event_rule.iam_changes.arn,
        aws_cloudwatch_event_rule.secret_changes.arn,
        aws_cloudwatch_event_rule.secret_reads_direct.arn,
        aws_cloudwatch_event_rule.secret_reads_assumed_role.arn,
      ]
    }
  }
}

resource "aws_sns_topic_policy" "audit" {
  arn    = aws_sns_topic.audit.arn
  policy = data.aws_iam_policy_document.sns.json
}

#############################
#### EventBridge targets ####
#############################

resource "aws_cloudwatch_event_target" "iam_changes" {
  rule      = aws_cloudwatch_event_rule.iam_changes.name
  target_id = "SendIamChangesAuditEmail"
  arn       = aws_sns_topic.audit.arn

  input_transformer {
    input_paths = {
      account = "$.account"
      detail  = "$.detail"
      region  = "$.region"
      time    = "$.time"
    }

    input_template = <<-EOT
      {
        "alert": "AWS CloudTrail audit event",
        "account": <account>,
        "time": <time>,
        "region": <region>,
        "cloudTrailDetail": <detail>
      }
    EOT
  }

  depends_on = [aws_sns_topic_policy.audit]
}

resource "aws_cloudwatch_event_target" "secret_changes" {
  rule      = aws_cloudwatch_event_rule.secret_changes.name
  target_id = "SendSecretChangesAuditEmail"
  arn       = aws_sns_topic.audit.arn

  input_transformer {
    input_paths = {
      account = "$.account"
      detail  = "$.detail"
      region  = "$.region"
      time    = "$.time"
    }

    input_template = <<-EOT
      {
        "alert": "AWS CloudTrail audit event",
        "account": <account>,
        "time": <time>,
        "region": <region>,
        "cloudTrailDetail": <detail>
      }
    EOT
  }

  depends_on = [aws_sns_topic_policy.audit]
}

resource "aws_cloudwatch_event_target" "secret_reads_direct" {
  rule      = aws_cloudwatch_event_rule.secret_reads_direct.name
  target_id = "SendDirectSecretReadsAuditEmail"
  arn       = aws_sns_topic.audit.arn

  input_transformer {
    input_paths = {
      account = "$.account"
      detail  = "$.detail"
      region  = "$.region"
      time    = "$.time"
    }

    input_template = <<-EOT
      {
        "alert": "AWS CloudTrail audit event",
        "account": <account>,
        "time": <time>,
        "region": <region>,
        "cloudTrailDetail": <detail>
      }
    EOT
  }

  depends_on = [aws_sns_topic_policy.audit]
}

resource "aws_cloudwatch_event_target" "secret_reads_assumed_role" {
  rule      = aws_cloudwatch_event_rule.secret_reads_assumed_role.name
  target_id = "SendAssumedRoleSecretReadsAuditEmail"
  arn       = aws_sns_topic.audit.arn

  input_transformer {
    input_paths = {
      account = "$.account"
      detail  = "$.detail"
      region  = "$.region"
      time    = "$.time"
    }

    input_template = <<-EOT
      {
        "alert": "AWS CloudTrail audit event",
        "account": <account>,
        "time": <time>,
        "region": <region>,
        "cloudTrailDetail": <detail>
      }
    EOT
  }

  depends_on = [aws_sns_topic_policy.audit]
}
