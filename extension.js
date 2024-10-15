const vscode = require('vscode');
const AiService = require('./services/AiService');
const OpaValidationService = require('./services/OpaValidationService');
const StorageService = require('./services/StorageService');

function activate(context) {
    // Register AI Assist command
    let aiAssistCommand = vscode.commands.registerCommand('extension.aiAssist', () => {
        AiService.showAiAssistPanel(context);
    });

    // Register OPA Validation command
    let opaValidationCommand = vscode.commands.registerCommand('extension.validateOpa', () => {
        OpaValidationService.showOpaValidationPanel(context);
    });

    // Register Storage Template Generator command
    let storageTemplateCommand = vscode.commands.registerCommand('extension.showStorageTemplateGenerator', () => {
        StorageService.showStorageTemplateGenerator(context);
    });

    // Push all commands to the context
    context.subscriptions.push(aiAssistCommand);
    context.subscriptions.push(opaValidationCommand);
    context.subscriptions.push(storageTemplateCommand);
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};
