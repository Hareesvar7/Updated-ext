const vscode = require('vscode');
const { runAiAssist } = require('./services/AiService');  // AI assist service
const { validateOpaPolicy } = require('./services/OpaService');  // OPA validation service

function activate(context) {
    console.log('OPA & AI assist extension is now active!');

    // Register AI assist command
    let aiAssistCommand = vscode.commands.registerCommand('extension.aiAssist', async () => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            const document = editor.document;
            const text = document.getText();
            const response = await runAiAssist(text);
            editor.edit(editBuilder => {
                const lastLine = document.lineAt(document.lineCount - 1);
                editBuilder.insert(lastLine.range.end, `\nAI Suggestion: ${response}`);
            });
        }
    });

    // Register OPA validation command
    let opaValidationCommand = vscode.commands.registerCommand('extension.validateOpa', async () => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            const document = editor.document;
            const filePath = document.uri.fsPath;
            const validationResults = await validateOpaPolicy(filePath);
            vscode.window.showInformationMessage(validationResults);
        }
    });

    // Register cloud storage template generation on document change
    let templateListener = vscode.workspace.onDidChangeTextDocument((event) => {
        const editor = vscode.window.activeTextEditor;
        if (editor && editor.document.languageId === 'rego') {
            const document = editor.document;
            const text = document.getText();
            const lastLine = document.lineAt(document.lineCount - 1);

            // AWS S3 template
            if (text.includes('aws_s3_template')) {
                const awsTemplate = `package aws.s3.policies

# Enforce S3 Access Points in VPC Only
deny[msg] { ... }
// Continue the rest of the template...
allow {
    not deny[_]
}`;
                insertTemplate(editor, lastLine, awsTemplate);
            }

            // Azure Blob Storage template
            if (text.includes('azure_blob_template')) {
                const azureTemplate = `package azure.blob.policies

# Enforce Secure Transfer Required
deny[msg] { ... }
// Continue the rest of the template...
allow {
    not deny[_]
}`;
                insertTemplate(editor, lastLine, azureTemplate);
            }

            // GCP Cloud Storage template
            if (text.includes('gcp_storage_template')) {
                const gcpTemplate = `package gcp.storage.policies

# Enforce Uniform Bucket-Level Access
deny[msg] { ... }
// Continue the rest of the template...
allow {
    not deny[_]
}`;
                insertTemplate(editor, lastLine, gcpTemplate);
            }
        }
    });

    // Add all commands and listeners to subscriptions
    context.subscriptions.push(aiAssistCommand, opaValidationCommand, templateListener);
}

// Utility function to insert the cloud storage template
function insertTemplate(editor, line, template) {
    editor.edit(editBuilder => {
        const startPos = new vscode.Position(line.lineNumber, 0);
        const endPos = new vscode.Position(line.lineNumber + 1, 0);
        editBuilder.replace(new vscode.Range(startPos, endPos), template);
    });
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};
