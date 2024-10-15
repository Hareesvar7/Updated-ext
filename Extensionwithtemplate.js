// src/extension.js

const vscode = require('vscode');
const StorageService = require('./commands/StorageService');

function activate(context) {
    const disposable = vscode.commands.registerCommand('extension.generateStorageTemplate', async (command) => {
        await StorageService.generateStorageTemplate(command);
    });

    context.subscriptions.push(disposable);
}

function deactivate() {}

module.exports = {
    activate,
    deactivate,
};
