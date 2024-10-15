class StorageTemplateService {
    constructor() {
        this.templates = {
            aws_s3_template: this.getAwsS3Template(),
            azure_storage_template: this.getAzureStorageTemplate(),
            gcp_storage_template: this.getGcpStorageTemplate(),
        };
    }

    getAwsS3Template() {
        return `package aws.s3.policies

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_access_point"
    not resource.change.after.vpc_configuration
    msg = sprintf("S3 Access Point '%s' must be configured in a VPC", [resource.change.after.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_access_point"
    not resource.change.after.public_access_block
    msg = sprintf("S3 Access Point '%s' must have public access blocks enabled", [resource.change.after.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.account_level_public_access_block
    msg = sprintf("S3 bucket '%s' must have account-level public access blocks enabled", [resource.change.after.bucket])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.after.acl != "private"
    msg = sprintf("S3 bucket '%s' must not use ACLs", [resource.change.after.bucket])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    action := resource.change.after.blacklisted_actions[_]
    msg = sprintf("S3 bucket '%s' contains blacklisted action '%s'", [resource.change.after.bucket, action])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.cross_region_replication.enabled
    msg = sprintf("S3 bucket '%s' must have cross-region replication enabled", [resource.change.after.bucket])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.default_lock.enabled
    msg = sprintf("S3 bucket '%s' must have default lock enabled", [resource.change.after.bucket])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.after.public_access_block.allow_public_acls == true
    msg = sprintf("S3 bucket '%s' must not allow public ACLs", [resource.change.after.bucket])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.logging.enabled
    msg = sprintf("S3 bucket '%s' must have logging enabled", [resource.change.after.bucket])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.mfa_delete.enabled
    msg = sprintf("S3 bucket '%s' must have MFA Delete enabled", [resource.change.after.bucket])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.server_side_encryption.enabled
    msg = sprintf("S3 bucket '%s' must have server-side encryption enabled", [resource.change.after.bucket])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.ssl_requests_only
    msg = sprintf("S3 bucket '%s' must enforce SSL requests only", [resource.change.after.bucket])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.versioning.enabled
    msg = sprintf("S3 bucket '%s' must have versioning enabled", [resource.change.after.bucket])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.default_encryption.kms_key_id
    msg = sprintf("S3 bucket '%s' must use KMS for default encryption", [resource.change.after.bucket])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.event_notifications
    msg = sprintf("S3 bucket '%s' must have event notifications enabled", [resource.change.after.bucket])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.last_backup_recovery_point
    msg = sprintf("S3 bucket '%s' must have a last backup recovery point created", [resource.change.after.bucket])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.lifecycle_policy
    msg = sprintf("S3 bucket '%s' must have a lifecycle policy configured", [resource.change.after.bucket])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.after.restore_time_target > 24
    msg = sprintf("S3 bucket '%s' must meet restore time target of 24 hours or less", [resource.change.after.bucket])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.logically_air_gapped
    msg = sprintf("S3 bucket '%s' must be in a logically air-gapped vault", [resource.change.after.bucket])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.backup_plan_protection
    msg = sprintf("S3 bucket '%s' must be protected by a backup plan", [resource.change.after.bucket])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.version_lifecycle_policy
    msg = sprintf("S3 bucket '%s' must have a version lifecycle policy configured", [resource.change.after.bucket])
}
`;
    }

    getAzureStorageTemplate() {
        return `package azure.storage.policies

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not resource.change.after.enable_https_traffic_only
    msg = sprintf("Azure Storage Account '%s' must enforce HTTPS traffic only", [resource.change.after.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not resource.change.after.public_access_block
    msg = sprintf("Azure Storage Account '%s' must have public access block enabled", [resource.change.after.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not resource.change.after.encryption.services.blob.enabled
    msg = sprintf("Azure Storage Account '%s' must have default encryption enabled for blob services", [resource.change.after.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not resource.change.after.blob_properties.delete_retention_policy.enabled
    msg = sprintf("Azure Storage Account '%s' must have soft delete enabled for blob services", [resource.change.after.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not resource.change.after.logging.read
    msg = sprintf("Azure Storage Account '%s' must have logging enabled", [resource.change.after.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not resource.change.after.private_endpoint_connections[_].private_endpoint.id
    msg = sprintf("Azure Storage Account '%s' must have a private endpoint connection", [resource.change.after.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not resource.change.after.geo_replication_enabled
    msg = sprintf("Azure Storage Account '%s' must have geo-replication enabled", [resource.change.after.name])
}
`;
    }

    getGcpStorageTemplate() {
    return `package gcp.storage.policies

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    not resource.change.after.uniform_bucket_level_access.enabled
    msg = sprintf("GCP Storage Bucket '%s' must have uniform bucket-level access enabled", [resource.change.after.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    not resource.change.after.encryption.default_kms_key_name
    msg = sprintf("GCP Storage Bucket '%s' must use customer-managed encryption keys by default", [resource.change.after.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    not resource.change.after.logging.log_bucket
    msg = sprintf("GCP Storage Bucket '%s' must have logging enabled", [resource.change.after.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    not resource.change.after.lifecycle_rule
    msg = sprintf("GCP Storage Bucket '%s' must have a lifecycle policy configured", [resource.change.after.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    resource.change.after.public_access_prevention != "enforced"
    msg = sprintf("GCP Storage Bucket '%s' must enforce public access prevention", [resource.change.after.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    not resource.change.after.retention_policy.is_locked
    msg = sprintf("GCP Storage Bucket '%s' must have a locked retention policy", [resource.change.after.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    not resource.change.after.versioning.enabled
    msg = sprintf("GCP Storage Bucket '%s' must have versioning enabled", [resource.change.after.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    resource.change.after.default_event_based_hold != true
    msg = sprintf("GCP Storage Bucket '%s' must have event-based holds enabled by default", [resource.change.after.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    not resource.change.after.autoclass.enabled
    msg = sprintf("GCP Storage Bucket '%s' must have autoclass enabled to manage storage class transitions", [resource.change.after.name])
}
`;
    }

