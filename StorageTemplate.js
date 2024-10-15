const vscode = require('vscode');
const storageService = require('../services/StorageService');
const storageTemplateService = require('../services/StorageTemplateService');

class StorageTemplateCommand {
    constructor() {
        this.keywords = storageService.keywords;
    }

    async insertTemplate(editor) {
        if (editor) {
            const document = editor.document;
            const position = editor.selection.active;
            const text = document.getText();
            let templateFound = false;

            for (const keyword of this.keywords) {
                if (text.includes(keyword)) {
                    const template = storageTemplateService.getTemplate(keyword);
                    if (template) {
                        await editor.edit(editBuilder => {
                            editBuilder.insert(position, template);
                        });
                        templateFound = true;
                        break;
                    }
                }
            }

            if (!templateFound) {
                vscode.window.showWarningMessage('Template not found');
            }
        }
    }
}

module.exports = new StorageTemplateCommand();
