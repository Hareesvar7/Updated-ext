function getTemplateForStorage(cloudProvider) {
    switch (cloudProvider) {
        case 'aws':
            return `
package aws.s3.policies

# 1. Enforce S3 Access Points in VPC Only
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_access_point"
    not resource.change.after.vpc_configuration
    msg = sprintf("S3 Access Point '%s' must be configured in a VPC", [resource.change.after.name])
}

# 2. Enforce Public Access Blocks on S3 Access Points
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_access_point"
    not resource.change.after.public_access_block
    msg = sprintf("S3 Access Point '%s' must have public access blocks enabled", [resource.change.after.name])
}
# ... Add more rules as needed for AWS S3
`;

        case 'azure':
            return `
package azure.blob.policies

# 1. Enforce Storage Account Configuration
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azure_storage_account"
    not resource.change.after.network_rules
    msg = sprintf("Azure Storage Account '%s' must have network rules configured", [resource.change.after.name])
}

# 2. Enforce Public Access Level
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azure_storage_account"
    resource.change.after.public_access != "None"
    msg = sprintf("Azure Storage Account '%s' must not allow public access", [resource.change.after.name])
}
# ... Add more rules as needed for Azure Blob Storage
`;

        case 'gcp':
            return `
package gcp.storage.policies

# 1. Enforce Bucket Location
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "gcp_storage_bucket"
    not resource.change.after.location
    msg = sprintf("GCP Storage Bucket '%s' must have a location specified", [resource.change.after.name])
}

# 2. Enforce Uniform Bucket-Level Access
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "gcp_storage_bucket"
    not resource.change.after.uniform_bucket_level_access.enabled
    msg = sprintf("GCP Storage Bucket '%s' must have uniform bucket-level access enabled", [resource.change.after.name])
}
# ... Add more rules as needed for GCP Storage
`;

        default:
            return '';
    }
}

module.exports = { getTemplateForStorage };
