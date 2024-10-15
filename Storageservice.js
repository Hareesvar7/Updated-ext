// src/commands/StorageService.js

const vscode = require('vscode');
const StorageTemplateService = require('../services/StorageTemplateService');

class StorageService {
    static async generateStorageTemplate(command) {
        const template = StorageTemplateService.getTemplate(command);
        if (template) {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                editor.edit(editBuilder => {
                    editBuilder.insert(editor.selection.active, template);
                });
            }
        } else {
            vscode.window.showErrorMessage('Template not found for the specified command.');
        }
    }
}

module.exports = StorageService;
