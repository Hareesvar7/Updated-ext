// StorageTemplateService.js

const vscode = require('vscode');

const templates = {
    aws_s3_template: `package aws.s3.policies

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

# Add additional rules as needed...

# Allow if no deny conditions are met
allow {
    not deny[_]
}`
};

// Function to get the template based on the keyword
function getTemplate(keyword) {
    return templates[keyword] || null;
}

// Export the function to be used in other files
module.exports = {
    getTemplate,
};
