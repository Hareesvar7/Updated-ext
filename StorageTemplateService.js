const vscode = require('vscode');

const templates = {
    aws_s3_template: `package aws.s3.policies

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    msg = sprintf("S3 bucket '%s' must have appropriate policies", [resource.change.after.bucket])
}
`,
    azure_storage_template: `package azure.storage.policies

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    msg = sprintf("Azure Storage Account '%s' must comply with security policies", [resource.change.after.name])
}
`,
    gcp_storage_template: `package gcp.storage.policies

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    msg = sprintf("GCP Cloud Storage Bucket '%s' must have secure settings", [resource.change.after.name])
}
};

function getTemplate(keyword) {
    return templates[keyword] || null;
}

module.exports = {
    getTemplate,
};
