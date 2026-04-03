// Dashboard-specific JavaScript functionality
const csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';

class DashboardManager {
    constructor(dashboardId) {
        this.dashboardId = dashboardId;
        this.currentSessionId = null;
        this.currentCsvData = null;
        this.currentSource = null;
        this.mappingRuleSets = [];
        this.selectedMappingRuleSetId = null;
        this.csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
        this.isTouchDevice = this.detectTouchDevice();
        this.lastSelectionRange = null;
        this.monthlyToastShown = false;
        this.securityToastShown = false;
        this.analyticsSessionId = null;
        this.init();
    }

    init() {
        this.setupPdfProcessing();
        this.setupAiChat();
        this.setupTableEditors();
        this.setupEventListeners();
        this.loadMappingRules();
    }

    detectTouchDevice() {
        const hasWindow = typeof window !== 'undefined';
        const hasNavigator = typeof navigator !== 'undefined';
        return (
            (hasWindow && 'ontouchstart' in window) ||
            (hasNavigator && navigator.maxTouchPoints > 0) ||
            (hasWindow && window.matchMedia && window.matchMedia('(pointer: coarse)').matches)
        );
    }

    async loadMappingRules() {
        try {
            const response = await ApiClient.mappingRules.list();
            this.mappingRuleSets = response.rule_sets || [];
            const defaultRuleSet = this.mappingRuleSets.find((ruleSet) => ruleSet.is_default) || this.mappingRuleSets[0];
            this.selectedMappingRuleSetId = defaultRuleSet ? defaultRuleSet.id : null;
            this.renderMappingRuleSelector();
        } catch (error) {
            debug.error('Failed to load mapping rules:', error);
        }
    }

    renderMappingRuleSelector() {
        const select = document.getElementById('mappingRuleSelect');
        const applyBtn = document.getElementById('applyMappingRulesBtn');
        const status = document.getElementById('mappingRuleStatus');
        if (!select) {
            return;
        }

        select.innerHTML = '';
        if (!this.mappingRuleSets.length) {
            select.disabled = true;
            if (applyBtn) {
                applyBtn.disabled = true;
            }
            if (status) {
                status.textContent = 'No mapping rules available yet.';
            }
            return;
        }

        this.mappingRuleSets.forEach((ruleSet) => {
            const option = document.createElement('option');
            option.value = ruleSet.id;
            option.textContent = ruleSet.is_default ? `${ruleSet.name} (Default)` : ruleSet.name;
            if (Number(ruleSet.id) === Number(this.selectedMappingRuleSetId)) {
                option.selected = true;
            }
            select.appendChild(option);
        });

        select.disabled = false;
        if (applyBtn) {
            applyBtn.disabled = !this.currentCsvData;
        }
        if (status) {
            const selected = this.getSelectedMappingRuleSet();
            status.textContent = selected
                ? `Using ${selected.name} for import categorization.`
                : 'Select a mapping rule set for import categorization.';
        }

        if (!select.dataset.bound) {
            select.addEventListener('change', async (event) => {
                this.selectedMappingRuleSetId = Number(event.target.value);
                await this.persistSelectedMappingRuleSet();
                this.renderMappingRuleSelector();
            });
            select.dataset.bound = 'true';
        }

        if (applyBtn && !applyBtn.dataset.bound) {
            applyBtn.addEventListener('click', async () => {
                await this.applySelectedMappingRulesToCurrentCsv(true);
            });
            applyBtn.dataset.bound = 'true';
        }
    }

    getSelectedMappingRuleSet() {
        return this.mappingRuleSets.find((ruleSet) => Number(ruleSet.id) === Number(this.selectedMappingRuleSetId)) || null;
    }

    async persistSelectedMappingRuleSet() {
        if (!this.selectedMappingRuleSetId) {
            return;
        }
        try {
            await ApiClient.mappingRules.update(this.selectedMappingRuleSetId, { is_default: true });
            this.mappingRuleSets = this.mappingRuleSets.map((ruleSet) => ({
                ...ruleSet,
                is_default: Number(ruleSet.id) === Number(this.selectedMappingRuleSetId)
            }));
        } catch (error) {
            debug.error('Failed to persist selected mapping rule set:', error);
        }
    }

    normalizeMappingText(value) {
        return String(value || '')
            .toLowerCase()
            .replace(/[^\w\s*|]/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
    }

    applyMappingRulesToCsv(csvData) {
        const selectedRuleSet = this.getSelectedMappingRuleSet();
        if (!selectedRuleSet || !csvData) {
            return { csvData, matchedRows: 0, totalRows: 0 };
        }

        const rows = this.parseCsvRows(csvData);
        if (!rows.length) {
            return { csvData, matchedRows: 0, totalRows: 0 };
        }

        const headers = rows[0];
        const dataRows = rows.slice(1);
        const descriptionIndex = headers.findIndex((header) => String(header).trim().toLowerCase() === 'description');
        const categoryIndex = headers.findIndex((header) => String(header).trim().toLowerCase() === 'category');
        if (descriptionIndex === -1 || categoryIndex === -1) {
            return { csvData, matchedRows: 0, totalRows: dataRows.length };
        }

        let matchedRows = 0;
        const updatedRows = dataRows.map((row) => {
            const nextRow = row.slice();
            while (nextRow.length < headers.length) {
                nextRow.push('');
            }
            const description = this.normalizeMappingText(nextRow[descriptionIndex]);
            if (!description) {
                return nextRow;
            }
            const existingCategory = String(nextRow[categoryIndex] || '').trim().toLowerCase();
            const shouldReplace = !existingCategory || existingCategory === 'misc' || existingCategory === 'uncategorized';
            if (!shouldReplace) {
                return nextRow;
            }

            for (const entry of (selectedRuleSet.entries || [])) {
                const tokens = String(entry.pattern || '')
                    .split('|')
                    .map((part) => this.normalizeMappingText(part))
                    .filter(Boolean);
                if (tokens.some((token) => description.includes(token))) {
                    nextRow[categoryIndex] = entry.category;
                    matchedRows += 1;
                    break;
                }
            }
            return nextRow;
        });

        return {
            csvData: this.buildCsvFromRows([headers, ...updatedRows]),
            matchedRows,
            totalRows: dataRows.length,
        };
    }

    buildCsvFromRows(rows) {
        return rows.map((row) => row.map((cell) => {
            const value = String(cell ?? '');
            if (value.includes(',') || value.includes('"') || value.includes('\n')) {
                return `"${value.replace(/"/g, '""')}"`;
            }
            return value;
        }).join(',')).join('\n');
    }

    async applySelectedMappingRulesToCurrentCsv(showToast = false) {
        if (!this.currentCsvData) {
            return;
        }
        const result = this.applyMappingRulesToCsv(this.currentCsvData);
        this.currentCsvData = result.csvData;
        this.showCsvPreview(this.currentCsvData);
        const status = document.getElementById('mappingRuleStatus');
        if (status) {
            status.textContent = `Applied ${result.matchedRows} mapping rule matches across ${result.totalRows} imported rows.`;
        }
        if (showToast) {
            Utils.showNotification(`Applied mapping rules to ${result.matchedRows} row(s).`, 'success');
        }
    }

    setupPdfProcessing() {
        // Setup two option layout
        this.setupOptionSelection();
        this.setupIngressToolsPanel();
        
        // Setup Google Sheets paste functionality
        const processSheetsBtn = document.getElementById('processSheetsData');
        const sheetsPasteText = document.getElementById('sheetsPasteText');
        const cancelSheetsBtn = document.getElementById('cancelSheets');
        
        if (processSheetsBtn && sheetsPasteText) {
            processSheetsBtn.addEventListener('click', this.handleSheetsPaste.bind(this));
            sheetsPasteText.addEventListener('paste', this.handleSheetsPaste.bind(this));
        }
        
        if (cancelSheetsBtn) {
            cancelSheetsBtn.addEventListener('click', () => this.cancelOption('paste'));
        }
        
        // Setup AI file upload
        const aiFileInput = document.getElementById('aiFileInput');
        const chooseFileBtn = document.getElementById('chooseFileBtn');
        const cancelAIBtn = document.getElementById('cancelAI');
        
        if (aiFileInput) {
            aiFileInput.addEventListener('change', this.handleAIUpload.bind(this));
        }
        
        // Setup choose file button
        if (chooseFileBtn) {
            chooseFileBtn.addEventListener('click', () => {
                debug.log('Choose file button clicked');
                aiFileInput.click();
            });
        }
        
        if (cancelAIBtn) {
            cancelAIBtn.addEventListener('click', () => this.cancelOption('upload'));
        }
    }

    setupIngressToolsPanel() {
        const layout = document.getElementById('ingressWorkspaceLayout');
        const helperColumn = document.getElementById('ingressHelperColumn');
        const helperRail = document.getElementById('ingressHelperRail');
        const helperToggleBtn = document.getElementById('ingressHelperCollapseBtn');
        const agentColumn = document.getElementById('ingressAgentColumn');
        const agentRail = document.getElementById('ingressAgentRail');
        const agentToggleBtn = document.getElementById('ingressAgentCollapseBtn');
        const mainColumn = document.getElementById('ingressMainColumn');
        const helperStorageKey = `ingressHelperCollapsed_${this.dashboardId}`;
        const agentStorageKey = `ingressAgentCollapsed_${this.dashboardId}`;
        if (!layout) return;

        const setColumnWidth = (element, widths) => {
            if (!element) {
                return;
            }
            ['col-lg-3', 'col-lg-6', 'col-lg-8', 'col-lg-10', 'col-lg-12'].forEach((className) => {
                element.classList.remove(className);
            });
            if (widths) {
                element.classList.add(widths);
            }
        };

        const syncRailState = () => {
            const helperCollapsed = window.localStorage.getItem(helperStorageKey) === 'true';
            const agentCollapsed = window.localStorage.getItem(agentStorageKey) === 'true';

            layout.classList.toggle('is-left-collapsed', helperCollapsed);
            layout.classList.toggle('is-right-collapsed', agentCollapsed);

            if (helperColumn) helperColumn.classList.toggle('is-collapsed', helperCollapsed);
            if (agentColumn) agentColumn.classList.toggle('is-collapsed', agentCollapsed);
            if (helperRail) helperRail.classList.toggle('is-collapsed', helperCollapsed);
            if (agentRail) agentRail.classList.toggle('is-collapsed', agentCollapsed);

            setColumnWidth(helperColumn, helperCollapsed ? '' : 'col-lg-3');
            setColumnWidth(agentColumn, agentCollapsed ? '' : 'col-lg-3');

            if (mainColumn) {
                if (helperCollapsed && agentCollapsed) {
                    setColumnWidth(mainColumn, 'col-lg-10');
                } else if (helperCollapsed || agentCollapsed) {
                    setColumnWidth(mainColumn, 'col-lg-8');
                } else {
                    setColumnWidth(mainColumn, 'col-lg-6');
                }
            }

            if (helperToggleBtn) {
                helperToggleBtn.setAttribute('aria-expanded', String(!helperCollapsed));
                helperToggleBtn.setAttribute('title', helperCollapsed ? 'Expand helper rail' : 'Collapse helper rail');
                helperToggleBtn.innerHTML = `<i class="fas fa-chevron-${helperCollapsed ? 'right' : 'left'}"></i>`;
            }

            if (agentToggleBtn) {
                agentToggleBtn.setAttribute('aria-expanded', String(!agentCollapsed));
                agentToggleBtn.setAttribute('title', agentCollapsed ? 'Expand import assistant' : 'Collapse import assistant');
                agentToggleBtn.innerHTML = `<i class="fas fa-chevron-${agentCollapsed ? 'left' : 'right'}"></i>`;
            }
        };

        syncRailState();

        if (helperToggleBtn) {
            helperToggleBtn.addEventListener('click', () => {
                const nextState = !(window.localStorage.getItem(helperStorageKey) === 'true');
                window.localStorage.setItem(helperStorageKey, nextState ? 'true' : 'false');
                syncRailState();
            });
        }

        if (agentToggleBtn) {
            agentToggleBtn.addEventListener('click', () => {
                const nextState = !(window.localStorage.getItem(agentStorageKey) === 'true');
                window.localStorage.setItem(agentStorageKey, nextState ? 'true' : 'false');
                syncRailState();
            });
        }
    }
    
    setupOptionSelection() {
        const optionCards = document.querySelectorAll('.option-card');
        optionCards.forEach(card => {
            const button = card.querySelector('button');
            button.addEventListener('click', (e) => {
                e.stopPropagation();
                const option = card.getAttribute('data-option');
                debug.log('Option card button clicked:', option);
                this.selectOption(option);
            });
            
            // Also allow clicking the entire card
            card.addEventListener('click', (e) => {
                if (e.target.tagName !== 'BUTTON') {
                    const option = card.getAttribute('data-option');
                    debug.log('Option card clicked:', option);
                    this.selectOption(option);
                }
            });
        });
    }
    
    selectOption(option) {
        debug.log('Selected option:', option);
        this.currentSource = option;
        
        // Hide all option cards
        const optionCards = document.querySelectorAll('.option-card');
        optionCards.forEach(card => {
            card.classList.add('d-none');
        });
        
        // Show the selected option interface
        if (option === 'paste') {
            this.showSheetsInterface();
        } else if (option === 'upload') {
            this.showAIInterface();
        }
    }
    
    showSheetsInterface() {
        const sheetsPasteArea = document.getElementById('sheetsPasteArea');
        sheetsPasteArea.classList.remove('d-none');
    }
    
    showAIInterface() {
        const aiUploadArea = document.getElementById('aiUploadArea');
        aiUploadArea.classList.remove('d-none');
    }
    
    cancelOption(option) {
        // Capture current IDs for cleanup before clearing local state
        const sessionId = this.currentSessionId;
        const extractionId = this.getStoredExtractionId();

        // Hide the current option interface
        if (option === 'paste') {
            const sheetsPasteArea = document.getElementById('sheetsPasteArea');
            sheetsPasteArea.classList.add('d-none');
            const sheetsPasteText = document.getElementById('sheetsPasteText');
            sheetsPasteText.value = '';
        } else if (option === 'upload') {
            const aiUploadArea = document.getElementById('aiUploadArea');
            aiUploadArea.classList.add('d-none');
            const aiFileInput = document.getElementById('aiFileInput');
            aiFileInput.value = '';
        }
        
        // Hide any CSV preview that might be showing
        const csvPreviewArea = document.getElementById('csvPreviewArea');
        if (csvPreviewArea) {
            csvPreviewArea.classList.add('d-none');
        }
        
        // Hide any processing area that might be showing
        const processingArea = document.getElementById('processingArea');
        if (processingArea) {
            processingArea.classList.add('d-none');
        }
        
        // Show all option cards again
        const optionCards = document.querySelectorAll('.option-card');
        optionCards.forEach(card => {
            card.classList.remove('d-none');
        });
        
        // Clear current data
        this.currentFile = null;
        this.currentFileType = null;
        this.currentCsvData = null;
        this.currentSessionId = null;
        this.currentSource = null;
        
        // Clear chat messages
        this.clearAiChat();
        
        // Clear localStorage for this dashboard and delete temp server data
        const localStorageKey = `pdf_extraction_${this.dashboardId}`;
        localStorage.removeItem(localStorageKey);
        debug.log('Cleared localStorage on cancel:', localStorageKey);
        this.cleanupAiState({ sessionId, extractionId });
        
        Utils.showNotification('Upload cancelled', 'info');
    }

    resetSheetsUI() {
        const optionCards = document.querySelectorAll('.option-card');
        optionCards.forEach(card => card.classList.remove('d-none'));

        const sheetsPasteArea = document.getElementById('sheetsPasteArea');
        const sheetsPasteText = document.getElementById('sheetsPasteText');
        const csvPreviewArea = document.getElementById('csvPreviewArea');
        const previewTable = document.getElementById('csvPreviewTable');
        const saveCsvBtn = document.getElementById('saveCsv');

        if (sheetsPasteArea) sheetsPasteArea.classList.add('d-none');
        const aiUploadArea = document.getElementById('aiUploadArea');
        if (sheetsPasteText) sheetsPasteText.value = '';
        if (aiUploadArea) aiUploadArea.classList.add('d-none');
        if (csvPreviewArea) csvPreviewArea.classList.add('d-none');
        if (previewTable) previewTable.innerHTML = '';
        if (saveCsvBtn) saveCsvBtn.disabled = true;
        this.currentSource = null;
    }
    
    async handleAIUpload(event) {
        const file = event.target.files[0];
        if (!file) {
            // User clicked the AI card but hasn't selected a file yet
            // Just show the upload interface and wait for file selection
            debug.log('AI upload interface shown, waiting for file selection');
            return;
        }
        
        const fileType = this.detectFileType(file);
        debug.log('AI processing - File type detected:', fileType);
        
        if (!fileType) {
            Utils.showNotification('Unsupported file type. Please upload CSV, Excel, or PDF files only.', 'warning');
            return;
        }
        
        // Clear chat box when new file is uploaded
        this.clearAiChat();
        
        // Clear localStorage for this dashboard when new file is uploaded
        const localStorageKey = `pdf_extraction_${this.dashboardId}`;
        localStorage.removeItem(localStorageKey);
        debug.log('Cleared localStorage for new file upload:', localStorageKey);
        
            // Store file info for later processing
            this.currentFile = file;
            this.currentFileType = fileType;
            this.currentSource = 'upload';
        
        // Add file upload message to chat
        this.addAiChatMessage('user', `Uploaded file: ${file.name} (${fileType.toUpperCase()})`);
        
        // For CSV files, we can load them immediately for preview
        if (fileType === 'csv') {
            await this.processCsvWithAI(file);
        } else if (fileType === 'excel') {
            // For Excel files, wait for user prompt before extraction
            this.addAiChatMessage('assistant', `I've received your Excel file. Please tell me what you'd like me to extract from it. For example: "Extract all transactions", "Find expenses over $50", or "Categorize the spending".`);
        } else if (fileType === 'pdf') {
            // For PDF files, wait for user prompt before extraction
            this.addAiChatMessage('assistant', `I've received your PDF file. Please tell me what you'd like me to extract from it. For example: "Extract all transactions", "Find expenses over $50", or "Categorize the spending".`);
        }
    }
    
    async processCsvWithAI(file) {
        try {
            const csvText = await this.readFileAsText(file);
            this.currentCsvData = csvText;
            await this.applySelectedMappingRulesToCurrentCsv();
            
            // Add CSV data to chat context
            this.addAiChatMessage('assistant', `I've loaded your CSV file. You can now import it directly, edit it manually, or ask the assistant to process it. For example: "Filter only transactions above $50", "Categorize expenses", or "Remove duplicate entries".`);
            
            // Show CSV preview
            this.showCsvPreview(this.currentCsvData);
            
        } catch (error) {
            debug.error('CSV processing error:', error);
            this.addAiChatMessage('assistant', 'Sorry, I encountered an error processing your CSV file. Please try again.');
        }
    }
    
    
    detectFileType(file) {
        const fileName = file.name.toLowerCase();
        const fileExtension = fileName.split('.').pop();
        
        if (fileExtension === 'csv' || file.type === 'text/csv') {
            return 'csv';
        } else if (fileExtension === 'pdf' || file.type === 'application/pdf') {
            return 'pdf';
        } else if (fileExtension === 'xlsx' || fileExtension === 'xls' || 
                   file.type === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' ||
                   file.type === 'application/vnd.ms-excel') {
            return 'excel';
        }
        
        return null;
    }
    readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = (e) => reject(e);
            reader.readAsText(file);
        });
    }

    getStoredExtractionId() {
        const localStorageKey = `pdf_extraction_${this.dashboardId}`;
        const storedState = localStorage.getItem(localStorageKey);
        if (!storedState) return null;
        try {
            const state = JSON.parse(storedState);
            return state.extraction_id || null;
        } catch (error) {
            debug.warn('Failed to parse stored extraction state', error);
            return null;
        }
    }

    async cleanupAiState(options = {}) {
        const sessionId = options.sessionId !== undefined ? options.sessionId : this.currentSessionId;
        const extractionId = options.extractionId !== undefined ? options.extractionId : this.getStoredExtractionId();
        
        if (!sessionId && !extractionId) {
            return;
        }
        
        try {
            await ApiClient.ai.cleanup(this.dashboardId, {
                session_id: sessionId,
                extraction_id: extractionId
            });
        } catch (error) {
            debug.warn('AI cleanup failed', error);
        } finally {
            // Always clear local state to avoid reusing stale IDs
            this.currentSessionId = null;
            const localStorageKey = `pdf_extraction_${this.dashboardId}`;
            localStorage.removeItem(localStorageKey);
        }
    }

    setupAiChat() {
        // Setup the new AI chat interface
        const sendAiMessageBtn = document.getElementById('sendAiMessage');
        const aiChatInput = document.getElementById('aiChatInput');
        
        if (sendAiMessageBtn && aiChatInput) {
            sendAiMessageBtn.addEventListener('click', this.sendAiChatMessage.bind(this));
            aiChatInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.sendAiChatMessage();
                }
            });
            // Seed a friendly intro if empty
            const chatMessages = document.getElementById('aiChatMessages');
            if (chatMessages && chatMessages.children.length === 0) {
                this.addAiChatMessage('assistant', 'Hello! Paste data or upload a file, then tell me how to clean, normalize, or categorize it.');
            }
        }
    }
    
    addAiChatMessage(role, content) {
        const chatMessages = document.getElementById('aiChatMessages');
        if (!chatMessages) return;
        const row = document.createElement('div');
        row.className = `ingress-chat-row ${role === 'user' ? 'is-user' : 'is-assistant'}`;
        const bubble = document.createElement('div');
        bubble.className = `ingress-chat-bubble ${role === 'user' ? 'is-user' : 'is-assistant'}`;
        const badge = document.createElement('span');
        badge.className = 'ingress-chat-badge';
        badge.textContent = role === 'user' ? 'You' : 'AI';
        const text = document.createElement('div');
        text.className = 'ingress-chat-text';
        text.textContent = content;
        bubble.appendChild(badge);
        bubble.appendChild(text);
        row.appendChild(bubble);
        chatMessages.appendChild(row);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
    
    clearAiChat() {
        const chatMessages = document.getElementById('aiChatMessages');
        if (chatMessages) {
            chatMessages.innerHTML = '';
        }
    }
    
    async sendAiChatMessage() {
        const aiChatInput = document.getElementById('aiChatInput');
        const message = aiChatInput.value.trim();
        
        if (!message) return;
        
        // Add user message to chat
        this.addAiChatMessage('user', message);
        aiChatInput.value = '';
        
        // Show loading state
        const sendBtn = document.getElementById('sendAiMessage');
        Utils.showLoading(sendBtn);
        
        try {
            // Check if we have a file to process
            if (this.currentFile && this.currentFileType === 'pdf') {
                // Process PDF with conversational AI
                await this.processPdfWithConversation(this.currentFile, message);
            } else if (this.currentFile && this.currentFileType === 'excel') {
                // Process Excel with AI using the user's prompt
                await this.processExcelWithPrompt(this.currentFile, message);
            } else if (this.currentCsvData) {
                // Process CSV with AI
                await this.processCsvWithPrompt(message);
            } else {
                // No data available yet
                this.addAiChatMessage('assistant', 'Please upload a file first before sending processing requests.');
            }
            
        } catch (error) {
            debug.error('AI chat processing error:', error);
            this.addAiChatMessage('assistant', 'Sorry, I encountered an error processing your request. Please try again.');
        } finally {
            Utils.hideLoading(sendBtn);
        }
    }
    
    async processPdfWithConversation(file, prompt) {
        try {
            // Check if we already have an extraction_id for this file
            const localStorageKey = `pdf_extraction_${this.dashboardId}`;
            const storedState = localStorage.getItem(localStorageKey);
            
            let extractionId;
            
            if (storedState) {
                const state = JSON.parse(storedState);
                // Check if the stored filename matches the current file
                if (state.filename === file.name) {
                    extractionId = state.extraction_id;
                    debug.log('Using existing extraction_id from localStorage:', extractionId);
                } else {
                    // Different file, clear old state
                    localStorage.removeItem(localStorageKey);
                    debug.log('New file detected, clearing old extraction state');
                }
            }
            
            if (!extractionId) {
                // Show processing status in chat
                this.addAiChatMessage('assistant', 'Processing PDF extraction...');
                
                // Get PDF extraction settings from UI
                const extractionMethod = document.getElementById('pdfExtractionMethod').value;
                const pageNumbers = document.getElementById('pdfPageNumbers').value.trim();
                
                debug.log('PDF extraction settings:', {
                    method: extractionMethod,
                    pageNumbers: pageNumbers
                });
                
                // Convert PDF to base64 for extraction
                const arrayBuffer = await file.arrayBuffer();
                
                // Use a safer method to convert array buffer to base64
                let base64Pdf = '';
                const bytes = new Uint8Array(arrayBuffer);
                const chunkSize = 8192; // Process in chunks to avoid argument limits
                
                for (let i = 0; i < bytes.length; i += chunkSize) {
                    const chunk = bytes.subarray(i, i + chunkSize);
                    base64Pdf += String.fromCharCode.apply(null, chunk);
                }
                
                base64Pdf = btoa(base64Pdf);
                
                // Step 1: Extract PDF text using the new endpoint with extraction settings
                const extractResponse = await fetch(`/api/dashboard/${this.dashboardId}/ai/extract-pdf`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': this.csrfToken
                    },
                    body: JSON.stringify({
                        pdf_data: base64Pdf,
                        filename: file.name,
                        extraction_method: extractionMethod,
                        page_numbers: pageNumbers
                    })
                });
                
                if (!extractResponse.ok) {
                    throw new Error(`PDF extraction failed: ${extractResponse.status}`);
                }
                
                const extractResult = await extractResponse.json();
                
                if (!extractResult.extraction_id) {
                    throw new Error('PDF extraction failed - no extraction ID returned');
                }
                
                extractionId = extractResult.extraction_id;
                
                // Store extraction_id in localStorage for future requests
                localStorage.setItem(localStorageKey, JSON.stringify({
                    extraction_id: extractionId,
                    filename: file.name,
                    dashboard_id: this.dashboardId,
                    extraction_method: extractionMethod,
                    page_numbers: pageNumbers
                }));
                
                debug.log('PDF extraction completed, stored extraction_id:', extractionId);
            } else {
                debug.log('Using existing extraction_id for chat:', extractionId);
            }
            
            // Step 2: Process chat with the extraction_id
            const chatResponse = await fetch(`/api/dashboard/${this.dashboardId}/ai/process-chat`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.csrfToken
                },
                body: JSON.stringify({
                    prompt: prompt,
                    extraction_id: extractionId
                })
            });
            
            if (!chatResponse.ok) {
                // If extraction_id is invalid, clear localStorage and restart
                if (chatResponse.status === 400) {
                    localStorage.removeItem(localStorageKey);
                    this.addAiChatMessage('assistant', 'Conversation state lost. Please upload the PDF again.');
                    return;
                }
                throw new Error(`AI processing failed: ${chatResponse.status}`);
            }
            
            const chatResult = await chatResponse.json();
            
            if (chatResult.csv_data) {
                this.currentCsvData = chatResult.csv_data;
                this.addAiChatMessage('assistant', chatResult.message || 'I\'ve processed your request. Here\'s the updated CSV:');
                this.showCsvPreview(chatResult.csv_data);
                Utils.showNotification('PDF processed successfully using conversational AI', 'success');
            } else {
                throw new Error('No CSV data returned from AI');
            }
            
        } catch (error) {
            debug.error('PDF conversational processing error:', error);
            this.addAiChatMessage('assistant', 'Error processing PDF with AI. Please try again.');
            this.resetUploadUI();
        }
    }
    
    async processExcelWithPrompt(file, prompt) {
        try {
            const processingArea = document.getElementById('processingArea');
            const progressBar = processingArea.querySelector('.progress-bar');

            // Show processing UI
            processingArea.classList.remove('d-none');

            // Convert Excel to base64 for AI processing
            const arrayBuffer = await file.arrayBuffer();
            
            // Use a safer method to convert array buffer to base64
            let base64Excel = '';
            const bytes = new Uint8Array(arrayBuffer);
            const chunkSize = 8192; // Process in chunks to avoid argument limits
            
            for (let i = 0; i < bytes.length; i += chunkSize) {
                const chunk = bytes.subarray(i, i + chunkSize);
                base64Excel += String.fromCharCode.apply(null, chunk);
            }
            
            base64Excel = btoa(base64Excel);
            
            // Show processing status
            progressBar.style.width = '50%';
            
            // Send Excel to AI for extraction with prompt
            const response = await fetch(`/api/dashboard/${this.dashboardId}/ai/extract-excel`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.csrfToken
                },
                body: JSON.stringify({
                    excel_data: base64Excel,
                    filename: file.name,
                    prompt: prompt
                })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const result = await response.json();
            
            // Update progress
            progressBar.style.width = '100%';
            
            if (result.csv_data) {
                this.currentCsvData = result.csv_data;
                this.addAiChatMessage('assistant', 'I\'ve extracted the data from your Excel file. Here\'s the processed CSV:');
                this.showCsvPreview(result.csv_data);
                Utils.showNotification('Excel file processed successfully using AI', 'success');
            } else {
                throw new Error('No CSV data returned from AI');
            }
            
        } catch (error) {
            debug.error('Excel processing error:', error);
            this.addAiChatMessage('assistant', 'Error processing Excel with AI. Please try again.');
            this.resetUploadUI();
        }
    }
    
    async processCsvWithPrompt(prompt) {
	debug.log('processing CSV with prompt');	
        try {
            if (!this.currentSessionId) {
                // Create AI session first
                const response = await ApiClient.ai.createSession(this.dashboardId, this.currentCsvData);
                this.currentSessionId = response.session_id;
            }
            
            // Send to AI API with current CSV data
            const response = await ApiClient.ai.processCsv(
                this.dashboardId,
                this.currentSessionId,
                prompt,
                this.currentCsvData
            );
            
            // Add AI response
            this.addAiChatMessage('assistant', response.message);
            
            // Update CSV preview if new data is provided
            if (response.processed_csv) {
                this.currentCsvData = response.processed_csv;
                this.showCsvPreview(response.processed_csv);
            }
            
        } catch (error) {
            debug.error('AI processing error:', error);
            const message = error?.response?.error || error?.message || 'Sorry, I encountered an error processing your request. Please try again.';
            this.addAiChatMessage('assistant', message);
        }
    }

    async setupTableEditors() {
        // Setup month dropdown first and get the selected month
        const selectedMonth = await this.setupMonthDropdown();
        
        // Setup user dropdown
        await this.setupUserDropdown();
        
        // Initialize Handsontable for monthly expenses with the selected month
        this.initMonthlyTable(selectedMonth);
        
        // Initialize DataTables for yearly view
        this.initYearlyTable();

        // Mobile-friendly row controls for Handsontable
        this.setupMobileMonthlyActions();

        // Analytics chat setup
        this.setupAnalytics();
    }

    setupMobileMonthlyActions() {
        if (!this.isTouchDevice) return;

        const addBtn = document.getElementById('mobileAddRow');
        const removeBtn = document.getElementById('mobileRemoveRow');
        const saveBtn = document.getElementById('mobileSaveRow');

        const buildSelection = (forAdd = false) => {
            if (!this.monthlyTable) {
                Utils.showNotification('Table not ready', 'warning');
                return null;
            }
            const sel = this.monthlyTable.getSelectedLast();
            const memo = this.lastSelectionRange;
            let selectionObj = null;

            if (sel && sel.length === 4) {
                const [r1, c1, r2, c2] = sel;
                selectionObj = {
                    start: { row: Math.min(r1, r2), col: Math.min(c1, c2) },
                    end: { row: Math.max(r1, r2), col: Math.max(c1, c2) }
                };
            } else if (memo) {
                selectionObj = memo;
            }

            if (!selectionObj) {
                Utils.showNotification('Tap a cell first to choose a row', 'info');
                return null;
            }

            let targetRow = selectionObj.start.row;
            if (forAdd) {
                targetRow = targetRow + 1; // mimic "insert below" for mobile
            }
            return [{
                start: { row: targetRow, col: selectionObj.start.col },
                end: { row: targetRow, col: selectionObj.end.col }
            }];
        };

        if (addBtn) {
            addBtn.addEventListener('click', () => {
                const selection = buildSelection(true);
                if (selection) {
                    this.handleRowAddition(selection);
                }
            });
        }

        if (removeBtn) {
            removeBtn.addEventListener('click', () => {
                const selection = buildSelection(false);
                if (selection) {
                    this.handleRowRemoval(selection);
                }
            });
        }

        if (saveBtn) {
            saveBtn.addEventListener('click', async () => {
                const selection = buildSelection(false);
                if (!selection || !this.monthlyTable) return;
                const rowIndex = selection[0].start.row;
                await this.saveNewRow(rowIndex);
            });
        }
    }

    setupEventListeners() {
        // Tab change events
        const tabs = document.querySelectorAll('#dashboardTabs button[data-bs-toggle="tab"]');
        tabs.forEach(tab => {
            tab.addEventListener('shown.bs.tab', (event) => {
                const target = event.target.getAttribute('data-bs-target');
                if (target === '#monthly') {
                    this.showMonthlyToast();
                    // Get the currently selected month from dropdown and load data for that month
                    const dropdownButton = document.getElementById('monthDropdown');
                    if (dropdownButton) {
                        const selectedMonth = this.getSelectedMonthFromDropdown();
                        if (selectedMonth) {
                            this.refreshMonthlyData(selectedMonth);
                        } else {
                            // If no month selected yet, load data for the default month
                            this.refreshMonthlyData();
                        }
                    }
                } else if (target === '#yearly') {
                    this.refreshYearlyData();
                } else if (target === '#ingress') {
                    this.showSecurityToast();
                } else if (target === '#analytics') {
                    this.focusAnalyticsInput();
                }
            });
        });
    }

    showMonthlyToast() {
        if (this.monthlyToastShown) return;
        const toastEl = document.getElementById('monthlyInfoToast');
        if (!toastEl || !window.bootstrap) return;
        const toast = bootstrap.Toast.getOrCreateInstance(toastEl);
        toast.show();
        this.monthlyToastShown = true;
    }

    showSecurityToast() {
        if (this.securityToastShown) return;
        const toastEl = document.getElementById('securityToast');
        if (!toastEl || !window.bootstrap) return;
        const toast = bootstrap.Toast.getOrCreateInstance(toastEl);
        toast.show();
        this.securityToastShown = true;
    }

    setupAnalytics() {
        this.analyticsChart = null;
        this.analyticsCtx = document.getElementById('analyticsChart');
        this.analyticsSummary = document.getElementById('analyticsSummary');
        this.analyticsLog = document.getElementById('analyticsChatLog');
        this.analyticsTable = document.getElementById('analyticsTable');
        this.analyticsTableInner = document.getElementById('analyticsTableInner');
        this.analyticsChartWrapper = document.getElementById('analyticsChartWrapper');
        this.analyticsMeta = document.getElementById('analyticsMeta');
        this.analyticsFindings = document.getElementById('analyticsFindings');
        this.analyticsWarnings = document.getElementById('analyticsWarnings');
        this.analyticsTrace = document.getElementById('analyticsTrace');

        const promptInput = document.getElementById('analyticsPrompt');
        const sendBtn = document.getElementById('analyticsSend');
        const cancelBtn = document.getElementById('analyticsCancel');

        if (sendBtn && promptInput) {
            sendBtn.addEventListener('click', () => this.handleAnalyticsPrompt());
            promptInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    this.handleAnalyticsPrompt();
                }
            });
        }

        if (cancelBtn) {
            cancelBtn.addEventListener('click', () => this.cancelAnalyticsSession());
        }
    }

    focusAnalyticsInput() {
        const promptInput = document.getElementById('analyticsPrompt');
        if (promptInput) {
            promptInput.focus();
        }
    }

    appendAnalyticsMessage(role, message) {
        if (!this.analyticsLog) return;
        const row = document.createElement('div');
        row.className = `ingress-chat-row ${role === 'user' ? 'is-user' : 'is-assistant'}`;
        const bubble = document.createElement('div');
        bubble.className = `ingress-chat-bubble ${role === 'user' ? 'is-user' : 'is-assistant'}`;
        const badge = document.createElement('span');
        badge.className = 'ingress-chat-badge';
        badge.textContent = role === 'user' ? 'You' : 'AI';
        const text = document.createElement('div');
        text.className = 'ingress-chat-text';
        text.textContent = message;
        bubble.appendChild(badge);
        bubble.appendChild(text);
        row.appendChild(bubble);
        this.analyticsLog.appendChild(row);
        this.analyticsLog.scrollTop = this.analyticsLog.scrollHeight;
    }

    clearAnalyticsChat() {
        if (this.analyticsLog) {
            this.analyticsLog.innerHTML = '';
        }
        if (this.analyticsSummary) {
            this.analyticsSummary.textContent = '';
        }
        if (this.analyticsChart) {
            this.analyticsChart.destroy();
            this.analyticsChart = null;
        }
        if (this.analyticsTable) {
            this.analyticsTable.classList.add('d-none');
        }
        if (this.analyticsChartWrapper) {
            this.analyticsChartWrapper.classList.remove('d-none');
        }
        if (this.analyticsFindings) {
            this.analyticsFindings.classList.add('d-none');
            this.analyticsFindings.innerHTML = '';
        }
        if (this.analyticsMeta) {
            this.analyticsMeta.classList.add('d-none');
            this.analyticsMeta.innerHTML = '';
        }
        if (this.analyticsWarnings) {
            this.analyticsWarnings.classList.add('d-none');
            this.analyticsWarnings.innerHTML = '';
        }
        if (this.analyticsTrace) {
            this.analyticsTrace.classList.add('d-none');
            this.analyticsTrace.textContent = '';
        }
    }

    async handleAnalyticsPrompt() {
        const promptInput = document.getElementById('analyticsPrompt');
        const prompt = (promptInput && promptInput.value.trim()) || '';
        if (!prompt) return;

        const sendBtn = document.getElementById('analyticsSend');
        if (sendBtn) sendBtn.disabled = true;
        if (promptInput) promptInput.disabled = true;

        this.appendAnalyticsMessage('user', prompt);

        try {
            const result = await ApiClient.analytics.query(this.dashboardId, prompt, this.analyticsSessionId);
            if (result.session_id) {
                this.analyticsSessionId = result.session_id;
            }
            this.appendAnalyticsMessage('assistant', result.summary || 'Chart ready');
            this.renderAnalyticsChart(result);
        } catch (error) {
            debug.error('Analytics query failed:', error);
            this.appendAnalyticsMessage('assistant', error.message || 'Failed to generate chart');
        } finally {
            if (sendBtn) sendBtn.disabled = false;
            if (promptInput) {
                promptInput.disabled = false;
                promptInput.value = '';
                promptInput.focus();
            }
        }
    }

    renderAnalyticsChart(payload) {
        if (!window.Chart) return;
        if (this.analyticsChart) {
            this.analyticsChart.destroy();
            this.analyticsChart = null;
        }

        const { chart_type, labels, data, summary, rows, datasets, findings, critic, trace, generation_mode, planner_mode, synthesis_mode, provider, model, token_usage } = payload;

        // Toggle views
        if (this.analyticsChartWrapper) {
            this.analyticsChartWrapper.classList.toggle('d-none', chart_type === 'table');
        }
        if (this.analyticsTable) {
            this.analyticsTable.classList.toggle('d-none', chart_type !== 'table');
        }

        if (chart_type === 'table' && this.analyticsTableInner) {
            const rowData = rows || [];
            const headers = rowData.length ? Object.keys(rowData[0]) : ['label', 'value'];
            let html = `<thead><tr>${headers.map(h => `<th>${Utils.escapeHtml(h.replace(/_/g, ' '))}</th>`).join('')}</tr></thead><tbody>`;
            rowData.forEach(r => {
                html += '<tr>';
                headers.forEach((header) => {
                    const value = r[header];
                    let formatted;
                    if (typeof value === 'number') {
                        const moneyLike = /amount|value|total|delta|current|prior/i.test(header);
                        formatted = moneyLike
                            ? Utils.formatCurrency(value)
                            : Utils.escapeHtml(value.toString());
                    } else {
                        formatted = Utils.escapeHtml(String(value ?? ''));
                    }
                    html += `<td>${formatted}</td>`;
                });
                html += '</tr>';
            });
            html += '</tbody>';
            this.analyticsTableInner.innerHTML = html;
            if (this.analyticsSummary) {
                this.analyticsSummary.textContent = summary || '';
            }
            this.renderAnalyticsInsights(findings, critic, trace, { generation_mode, planner_mode, synthesis_mode, provider, model, token_usage });
            return;
        }

        if (!this.analyticsCtx) return;

        const colors = [
            '#4154f1', '#2db6fa', '#ff771d', '#3f51b5', '#00bcd4',
            '#4caf50', '#f44336', '#9c27b0', '#ff9800', '#009688'
        ];

        let finalDatasets = datasets;
        if (!finalDatasets || finalDatasets.length === 0) {
            finalDatasets = [{
                label: 'Amount',
                data: data || [],
                backgroundColor: chart_type === 'pie' ? colors : colors[0],
                borderColor: chart_type === 'pie' ? '#fff' : colors[0],
                borderWidth: chart_type === 'pie' ? 1 : 2,
                tension: 0.3,
                fill: chart_type === 'pie'
            }];
        } else {
            // Assign colors if multiple series
            finalDatasets = finalDatasets.map((ds, idx) => ({
                ...ds,
                backgroundColor: chart_type === 'pie'
                    ? colors
                    : colors[idx % colors.length],
                borderColor: chart_type === 'pie'
                    ? '#fff'
                    : colors[idx % colors.length],
                borderWidth: chart_type === 'pie' ? 1 : 2,
                tension: 0.3,
                fill: chart_type === 'pie'
            }));
        }

        this.analyticsChart = new Chart(this.analyticsCtx, {
            type: chart_type === 'pie' ? 'pie' : (chart_type === 'bar' ? 'bar' : 'line'),
            data: {
                labels: labels || [],
                datasets: finalDatasets
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: true },
                    tooltip: { mode: 'index', intersect: false }
                },
                scales: chart_type === 'pie' ? {} : {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            callback: (val) => Utils.formatCurrency(val)
                        }
                    }
                }
            }
        });

        if (this.analyticsSummary) {
            this.analyticsSummary.textContent = summary || '';
        }
        this.renderAnalyticsInsights(findings, critic, trace, { generation_mode, planner_mode, synthesis_mode, provider, model, token_usage });
    }

    renderAnalyticsInsights(findings, critic, trace, metadata = {}) {
        if (this.analyticsMeta) {
            const chips = [];
            if (metadata.generation_mode) {
                chips.push(`<span class="badge rounded-pill text-bg-${metadata.generation_mode === 'ai_assisted' ? 'primary' : 'secondary'}">Generation: ${Utils.escapeHtml(metadata.generation_mode)}</span>`);
            }
            if (metadata.provider) {
                chips.push(`<span class="badge rounded-pill text-bg-light border text-dark">Provider: ${Utils.escapeHtml(metadata.provider)}</span>`);
            }
            if (metadata.model) {
                chips.push(`<span class="badge rounded-pill text-bg-light border text-dark">Model: ${Utils.escapeHtml(metadata.model)}</span>`);
            }
            if (metadata.token_usage && metadata.token_usage.total_tokens) {
                chips.push(`<span class="badge rounded-pill text-bg-light border text-dark">Tokens: ${Utils.escapeHtml(String(metadata.token_usage.total_tokens))}</span>`);
            }
            if (metadata.planner_mode) {
                chips.push(`<span class="badge rounded-pill text-bg-light border text-dark">Planner: ${Utils.escapeHtml(metadata.planner_mode)}</span>`);
            }
            if (metadata.synthesis_mode) {
                chips.push(`<span class="badge rounded-pill text-bg-light border text-dark">Synthesis: ${Utils.escapeHtml(metadata.synthesis_mode)}</span>`);
            }
            if (chips.length) {
                this.analyticsMeta.innerHTML = `<div class="d-flex flex-wrap gap-2">${chips.join('')}</div>`;
                this.analyticsMeta.classList.remove('d-none');
            } else {
                this.analyticsMeta.classList.add('d-none');
                this.analyticsMeta.innerHTML = '';
            }
        }

        if (this.analyticsFindings) {
            if (findings && findings.length) {
                const cards = findings.map((finding) => `
                    <div class="border rounded-3 p-3 mb-2 bg-light">
                        <div class="fw-semibold mb-1">${Utils.escapeHtml(finding.title || 'Finding')}</div>
                        <div class="small text-muted">${Utils.escapeHtml(finding.detail || '')}</div>
                    </div>
                `).join('');
                this.analyticsFindings.innerHTML = `<div class="fw-semibold small text-uppercase text-muted mb-2">Key Findings</div>${cards}`;
                this.analyticsFindings.classList.remove('d-none');
            } else {
                this.analyticsFindings.classList.add('d-none');
                this.analyticsFindings.innerHTML = '';
            }
        }

        if (this.analyticsWarnings) {
            const warnings = (critic && critic.warnings) || [];
            if (warnings.length) {
                const items = warnings.map((warning) => `<li>${Utils.escapeHtml(warning)}</li>`).join('');
                this.analyticsWarnings.innerHTML = `
                    <div class="alert alert-warning mb-0">
                        <div class="fw-semibold mb-1">Caveats</div>
                        <ul class="mb-0 ps-3">${items}</ul>
                    </div>
                `;
                this.analyticsWarnings.classList.remove('d-none');
            } else {
                this.analyticsWarnings.classList.add('d-none');
                this.analyticsWarnings.innerHTML = '';
            }
        }

        if (this.analyticsTrace) {
            const tools = (trace && trace.tools_used) || [];
            const parts = [];
            if (tools.length) {
                parts.push(`Trace: ${tools.join(' -> ')}`);
            }
            if (parts.length) {
                this.analyticsTrace.textContent = parts.join(' | ');
                this.analyticsTrace.classList.remove('d-none');
            } else {
                this.analyticsTrace.classList.add('d-none');
                this.analyticsTrace.textContent = '';
            }
        }
    }

    async cancelAnalyticsSession() {
        if (!this.analyticsSessionId) {
            this.appendAnalyticsMessage('assistant', 'No active analytics session to cancel.');
            this.clearAnalyticsChat();
            return;
        }
        try {
            await ApiClient.analytics.cancel(this.dashboardId, this.analyticsSessionId);
            this.appendAnalyticsMessage('assistant', 'Analytics context cleared.');
            this.analyticsSessionId = null;
            this.clearAnalyticsChat();
        } catch (error) {
            debug.error('Failed to cancel analytics session:', error);
            this.appendAnalyticsMessage('assistant', 'Could not clear context. Try again.');
        }
    }

    getSelectedMonthFromDropdown() {
        const dropdownButton = document.getElementById('monthDropdown');
        if (!dropdownButton) return null;

        const dataAttr = dropdownButton.getAttribute('data-month');
        if (dataAttr) return dataAttr;
        
        // Extract month from dropdown button text
        const buttonText = dropdownButton.textContent.trim();
        const monthMatch = buttonText.match(/(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}/);
        if (monthMatch) {
            // Convert month name to YYYY-MM format
            const [monthName, year] = monthMatch[0].split(' ');
            const monthNames = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
            const monthNum = (monthNames.indexOf(monthName) + 1).toString().padStart(2, '0');
            return `${year}-${monthNum}`;
        }
        return null;
    }

    async handleSheetsPaste(event) {
        let pastedData = '';
        
        if (event.type === 'paste') {
            // Get pasted data from clipboard
            pastedData = (event.clipboardData || window.clipboardData).getData('text');
        } else {
            // Get data from textarea
            const sheetsPasteText = document.getElementById('sheetsPasteText');
            pastedData = sheetsPasteText ? sheetsPasteText.value.trim() : '';
        }
        
        if (!pastedData) {
            Utils.showNotification('Please paste some data first', 'warning');
            return;
        }

        try {
            // Process Google Sheets data (tab-separated values)
            const csvData = this.convertSheetsToCsv(pastedData);
            this.currentCsvData = csvData;
            this.currentSource = 'paste';
            await this.applySelectedMappingRulesToCurrentCsv();
            
            // Show CSV preview
            this.showCsvPreview(this.currentCsvData);
            this.addAiChatMessage('assistant', 'Pasted data loaded. You can import it as-is, edit it directly, or ask the assistant to clean and categorize it.');
            
            Utils.showNotification('Google Sheets data processed successfully', 'success');
        } catch (error) {
            debug.error('Error processing Google Sheets data:', error);
            Utils.showNotification('Error processing Google Sheets data', 'danger');
        }
    }

    convertSheetsToCsv(sheetsData) {
        // Google Sheets data is typically tab-separated
        const lines = sheetsData.split('\n').filter(line => line.trim());
        const csvRows = [];
        
        // Add headers
        csvRows.push('Date,Description,Amount,Category');
        
        // Process each line
        lines.forEach(line => {
            const cells = line.split('\t').map(cell => cell.trim());
            
            if (cells.length >= 4) {
                const date = cells[0] || '';
                // Handle the case where there's an empty column between date and description
                let description = '';
                let amount = '';
                let category = '';
                
                // Find the description (first non-empty cell after date)
                for (let i = 1; i < cells.length; i++) {
                    const cell = cells[i];
                    if (cell && !cell.replace('.', '').replace('-', '').match(/^\d+$/)) {
                        description = cell;
                        break;
                    }
                }
                
                // Find amount (numeric value)
                for (let i = 1; i < cells.length; i++) {
                    const cell = cells[i].replace('$', '');
                    if (cell && cell.replace('.', '').replace('-', '').match(/^\d+$/)) {
                        amount = cell;
                        break;
                    }
                }
                
                // Find category (last non-empty cell)
                for (let i = cells.length - 1; i > 0; i--) {
                    const cell = cells[i];
                    if (cell && cell !== description && cell !== amount) {
                        category = this.normalizeCategory(cell);
                        break;
                    }
                }
                
                // Only add if we have at least a description or amount
                if (description || amount) {
                    csvRows.push(`"${date}","${description}","${amount}","${category}"`);
                }
            } else if (cells.length >= 3) {
                // Format: date, description, amount (no category)
                const date = cells[0] || '';
                const description = cells[1] || '';
                let amount = cells[2] || '';
                
                // Clean up amount - remove $ sign if present
                amount = amount.replace('$', '');
                
                if (description || amount) {
                    csvRows.push(`"${date}","${description}","${amount}",""`);
                }
            }
        });
        
        return csvRows.join('\n');
    }

    normalizeCategory(label) {
        if (!label) return '';
        const cleaned = label.toString().trim().toLowerCase();
        const stripped = cleaned
            .replace(/[^\w\s]/g, ' ') // remove punctuation like commas/periods
            .replace(/\s+/g, ' ')
            .trim();
        const singularish = stripped.endsWith('s') && stripped.length > 4 ? stripped.slice(0, -1) : stripped;
        
        const aliases = {
            'restaurant': 'restaurant',
            'restaurants': 'restaurant',
            'dining': 'restaurant',
            'food out': 'restaurant',
            'utility': 'utility',
            'utilities': 'utility',
            'internet': 'utility',
            'wifi': 'utility',
            'water': 'utility',
            'electric': 'utility',
            'electricity': 'utility',
            'power': 'utility',
            'gas bill': 'utility',
            'grocery': 'grocery',
            'groceries': 'grocery',
            'market': 'grocery',
            'fuel': 'gas',
            'petrol': 'gas',
            'transport': 'transport',
            'transportation': 'transport',
            'transit': 'transport',
            'uber': 'transport',
            'lyft': 'transport',
            'taxi': 'transport',
            'bus': 'transport',
            'train': 'transport',
            'home exp': 'home exp',
            'home expense': 'home exp',
            'home expenses': 'home exp',
            'home setup': 'home setup',
            'furniture': 'home setup',
            'service': 'service',
            'services': 'service',
            'shopping': 'shopping',
            'retail': 'shopping',
            'vacation': 'vacation',
            'travel': 'vacation',
            'trip': 'vacation',
            'car': 'car',
            'auto': 'car',
            'vehicle': 'car',
            'gym': 'gym',
            'fitness': 'gym',
            'hospital': 'hospital',
            'medical': 'hospital',
            'health': 'hospital',
            'mortgage': 'mortgage',
            'rent': 'rent',
            'misc': 'misc',
            'miscellaneous': 'misc',
            'other': 'misc'
        };
        
        return aliases[stripped] || aliases[singularish] || stripped || cleaned;
    }

    parseCsvRows(csvData) {
        return csvData
            .split('\n')
            .filter(line => line.trim() !== '')
            .map(line => line
                // Split on commas that are not inside quotes
                .split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/)
                .map(cell => cell.replace(/^"|"$/g, '').replace(/""/g, '"'))
            );
    }

    getValidExpenseCategories() {
        return ['car', 'gas', 'grocery', 'home exp', 'home setup', 'gym', 'hospital', 'misc', 'rent', 'mortgage', 'restaurant', 'service', 'shopping', 'transport', 'utility', 'vacation'];
    }

    showCsvPreview(csvData) {
        const processingArea = document.getElementById('processingArea');
        const csvPreviewArea = document.getElementById('csvPreviewArea');
        const previewTable = document.getElementById('csvPreviewTable');
        
        processingArea.classList.add('d-none');
        csvPreviewArea.classList.remove('d-none');
        
        // Parse CSV and create editable table preview
        const rows = this.parseCsvRows(csvData);
        const categories = this.getValidExpenseCategories();
        let tableHtml = '';
        
        rows.forEach((row, index) => {
            tableHtml += index === 0 ? '<tr>' : '<tr data-preview-row="true">';
            row.forEach((cell, cellIndex) => {
                if (index === 0) {
                    tableHtml += `<th>${cell}</th>`;
                } else {
                    if (cellIndex === 3) {
                        const options = categories.map((category) => (
                            `<option value="${category}" ${String(cell || '').toLowerCase() === category ? 'selected' : ''}>${category}</option>`
                        )).join('');
                        tableHtml += `<td><select class="preview-select" data-col="${cellIndex}">${options}</select></td>`;
                    } else {
                        const escaped = Utils.escapeHtml(cell || '');
                        tableHtml += `<td><input class="preview-input" data-col="${cellIndex}" type="text" value="${escaped}"></td>`;
                    }
                }
            });
            if (index === 0) {
                tableHtml += '<th>Remove</th>';
            } else {
                tableHtml += `<td class="text-center"><button type="button" class="btn btn-sm btn-outline-danger preview-remove-btn" aria-label="Remove row" title="Remove row"><i class="fas fa-trash"></i></button></td>`;
            }
            tableHtml += '</tr>';
        });
        
        previewTable.innerHTML = tableHtml;

        previewTable.querySelectorAll('.preview-input, .preview-select').forEach((element) => {
            const eventName = element.tagName === 'SELECT' ? 'change' : 'input';
            element.addEventListener(eventName, () => {
                this.updateCsvFromPreviewTable();
            });
        });

        previewTable.querySelectorAll('.preview-remove-btn').forEach((button) => {
            button.addEventListener('click', () => {
                button.closest('tr')?.remove();
                this.updateCsvFromPreviewTable();
            });
        });

        // Setup save data button
        const saveBtn = document.getElementById('saveCsv');
        if (saveBtn) {
            saveBtn.onclick = async () => {
                const originalText = saveBtn.textContent;
                saveBtn.disabled = true;
                saveBtn.textContent = 'Saving...';
                try {
                    this.updateCsvFromPreviewTable();
                    await this.saveCsvDataDirectly(this.currentCsvData);
                } finally {
                    saveBtn.disabled = false;
                    saveBtn.textContent = originalText;
                }
            };
        }
    }
    
    async saveCsvDataDirectly(csvData) {
        try {
            const validCategories = this.getValidExpenseCategories();
            
            // Parse CSV data directly
            const rows = this.parseCsvRows(csvData);
            const headers = rows[0] || [];
            const dataRows = rows.slice(1);
            
            // Convert to expense objects
            const expenses = [];
            const invalidCategories = [];
            
            dataRows.forEach((row, index) => {
                if (row.length >= 3) {
                    // Parse date from MM/DD/YYYY format to YYYY-MM-DD format
                    let date = row[0];
                    if (date && date.includes('/')) {
                        const parts = date.split('/');
                        if (parts.length === 3) {
                            const month = parts[0].padStart(2, '0');
                            const day = parts[1].padStart(2, '0');
                            const year = parts[2].length === 2 ? '20' + parts[2] : parts[2];
                            date = `${year}-${month}-${day}`;
                        }
                    }
                    
                    const expense = {
                        date: date,
                        description: row[1],
                        amount: parseFloat(row[2]) || 0,
                        category: row[3] || 'misc'
                    };
                    
                    // Validate category
                    if (expense.category && !validCategories.includes(expense.category.toLowerCase())) {
                        invalidCategories.push({
                            row: index + 2, // +2 because of header row and 0-based index
                            category: expense.category,
                            description: expense.description
                        });
                        return; // Skip this expense
                    }
                    
                    // More lenient validation - only require description and amount
                    if (expense.description && expense.amount > 0) {
                        expenses.push(expense);
                    }
                }
            });
            
            // Show error if invalid categories found
            if (invalidCategories.length > 0) {
                const errorMessage = `Invalid categories found in ${invalidCategories.length} row(s). Please fix these before saving:\n\n` +
                    invalidCategories.map(item => 
                        `Row ${item.row}: "${item.category}" (Description: "${item.description}")`
                    ).join('\n');
                
                Utils.showNotification(errorMessage, 'danger', 10000); // Show for 10 seconds
                return;
            }
            
            if (expenses.length === 0) {
                Utils.showNotification('No valid expenses to save. Please check if your data has descriptions and amounts.', 'warning');
                return;
            }
            
            // Save all expenses in one bulk call
            let savedCount = 0;
            try {
                const result = await ApiClient.expenses.bulkCreate(this.dashboardId, expenses);
                debug.log('Bulk save result:', result);
                savedCount = result.saved || 0;
                if (result.errors && result.errors.length) {
                    Utils.showNotification(`Saved ${savedCount} expenses. ${result.errors.length} failed validation.`, 'warning');
                } else {
                    Utils.showNotification(`Successfully saved ${savedCount} expenses to the database`, 'success');
                }
            } catch (error) {
                debug.error('Error saving expense (bulk):', error);
                debug.error('Error details (bulk):', error.message);
                Utils.showNotification('Error saving data to database', 'danger');
                return;
            }
            
            debug.log(`Total expenses saved (direct): ${savedCount}`);
            
            // Refresh all components after data ingress
            await this.refreshAllComponents();
            
            // Full reset of Sheets upload UI
            this.resetSheetsUI();
            
            // Cleanup temporary AI data once saved
            this.cleanupAiState();
            
        } catch (error) {
            debug.error('Error saving CSV data:', error);
            Utils.showNotification('Error saving data to database', 'danger');
        }
    }

    async refreshAllComponents() {
        debug.log('Refreshing all dashboard components after data ingress');
        
        try {
            // 1. Refresh month dropdown
            const refreshedMonth = await this.setupMonthDropdown();
            
            // 2. Refresh monthly table with current selected month
            const selectedMonth = refreshedMonth || this.getSelectedMonthFromDropdown();
            if (selectedMonth) {
                await this.refreshMonthlyData(selectedMonth);
            } else {
                // If no month selected, refresh with default month
                await this.refreshMonthlyData();
            }
            
            // 3. Refresh yearly table
            await this.initYearlyTable();
            
            Utils.showNotification('All dashboard components refreshed with new data', 'success');
            
        } catch (error) {
            debug.error('Error refreshing components:', error);
            Utils.showNotification('Error refreshing dashboard components', 'danger');
        }
    }

    updateCsvFromPreviewTable() {
        const previewTable = document.getElementById('csvPreviewTable');
        if (!previewTable) return;

        const rows = [];
        const headerCells = Array.from(previewTable.querySelectorAll('tr:first-child th'))
            .slice(0, 4)
            .map((cell) => cell.textContent.trim());
        if (!headerCells.length) {
            return;
        }
        rows.push(headerCells);

        previewTable.querySelectorAll('tr[data-preview-row="true"]').forEach((row) => {
            const cells = [];
            row.querySelectorAll('[data-col]').forEach((input) => {
                cells.push(input.value ?? '');
            });
            if (cells.some((value) => String(value).trim() !== '')) {
                rows.push(cells);
            }
        });

        this.currentCsvData = this.buildCsvFromRows(rows);
    }


    initMonthlyTable(selectedMonth = null) {
        debug.log('=== initMonthlyTable() called with selectedMonth:', selectedMonth, '===');
        const container = document.getElementById('monthlyExpensesTable');
        if (!container) {
            debug.error('Monthly table container not found!');
            return;
        }

        const isTouch = this.isTouchDevice;
        // Initialize empty table - data will be loaded from API
        this.monthlyTable = new Handsontable(container, {
            data: [],
            columns: [
                {
                    data: 'date',
                    type: 'date',
                    dateFormat: 'YYYY-MM-DD',
                    correctFormat: true,
                    width: 120
                },
                {
                    data: 'category',
                    type: 'dropdown',
                    source: ['car', 'gas', 'grocery', 'home exp', 'home setup', 'gym', 'hospital', 'misc', 'rent', 'mortgage', 'restaurant', 'service', 'shopping', 'transport', 'utility', 'vacation'],
                    width: 120,
                    filter: 'select'
                },
                {
                    data: 'amount',
                    type: 'numeric',
                    numericFormat: {
                        pattern: '$0,0.00'
                    },
                    width: 100
                },
                {
                    data: 'description',
                    type: 'text',
                    filter: 'text'
                },
                {
                    data: 'user_name',
                    type: 'text',
                    readOnly: true,
                    width: 120
                },
                {
                    data: 'id',
                    type: 'numeric',
                    readOnly: true,
                    width: 80
                }
            ],
            colHeaders: ['Date', 'Category', 'Amount', 'Description', 'User', 'ID'],
            dropdownMenu: [
                'filter_by_condition',
                'filter_action_bar',
                'filter_by_value',
                'filter_operators'
            ],
            filters: true,
            rowHeaders: true,
            contextMenu: {
                items: {
                    'row_above': {
                        name: 'Insert row above',
                        callback: (key, selection) => {
                            debug.log('Insert row above context menu triggered:', selection);
                            this.handleRowAddition(selection);
                        }
                    },
                    'row_below': {
                        name: 'Insert row below',
                        callback: (key, selection) => {
                            debug.log('Insert row below context menu triggered:', selection);
                            this.handleRowAddition(selection);
                        }
                    },
                    'remove_row': {
                        name: 'Remove row',
                        callback: (key, selection) => {
                            debug.log('Remove row context menu triggered:', selection);
                            this.handleRowRemoval(selection);
                        }
                    },
                    'sep1': '---------',
                    'alignment': {}
                }
            },
            manualColumnResize: !isTouch,
            manualRowMove: !isTouch,
            licenseKey: 'non-commercial-and-evaluation',
            height: 'auto', // Natural height so long lists aren't clipped; page scrolls instead
            renderAllRows: true,
            stretchH: 'all',
            preventOverflow: 'horizontal',
            selectionMode: isTouch ? 'single' : 'range',
            className: isTouch ? 'htTouchFriendly' : '',
            rowHeights: isTouch ? 44 : undefined,
            afterChange: (changes, source) => {
                debug.log('Handsontable afterChange called:', { 
                    changes: changes, 
                    source: source,
                    tableData: this.monthlyTable ? this.monthlyTable.getData() : 'No table'
                });
                
                // Only process user edits, ignore programmatic changes
                if (source === 'edit' && changes && changes.length > 0) {
                    debug.log('Valid user edit detected, processing individual changes');
                    debug.log('Changes details:', changes);
                    
                    // Process each change individually
                    changes.forEach(change => {
                        const [row, prop, oldValue, newValue] = change;
                        const rowData = this.monthlyTable.getDataAtRow(row);
                        const rowId = rowData[rowData.length - 1]; // ID is in last column
                        
                        if (rowId) {
                            // Convert row data to object format
                            const expenseData = {
                                date: rowData[0],
                                description: rowData[3],
                                amount: rowData[2],
                                category: rowData[1]
                            };
                            
                            debug.log('Calling updateMonthlyChanges for row ID:', rowId, 'with data:', expenseData);
                            this.updateMonthlyChanges(rowId, expenseData);
                        } else {
                            debug.log('No row ID found for row:', row, 'skipping update');
                        }
                    });
                } else if (source !== 'loadData' && source !== 'autofill' && source !== 'empty') {
                    debug.log('Ignoring non-edit change:', {
                        source: source,
                        changesCount: changes ? changes.length : 0,
                        changes: changes
                    });
                }
            },
            
            // Add additional event listeners for better change detection
            afterBeginEditing: (row, column) => {
                debug.log('Cell editing started:', { row, column });
            },
            
            afterSelection: (row, column, row2, column2, preventScrolling) => {
                debug.log('Cell selected:', { row, column });
                this.lastSelectionRange = {
                    start: { row: Math.min(row, row2), col: Math.min(column, column2) },
                    end: { row: Math.max(row, row2), col: Math.max(column, column2) }
                };
            },
            
        });

        // If a month is selected, load data for that month
        if (selectedMonth) {
            debug.log('Loading data for selected month:', selectedMonth);
            this.refreshMonthlyData(selectedMonth);
        } else {
            debug.log('No month selected, table remains empty');
        }

    }

    async setupMonthDropdown() {
        debug.log('=== setupMonthDropdown() called ===');
        const dropdownMenu = document.getElementById('monthDropdownMenu');
        const dropdownButton = document.getElementById('monthDropdown');
        
        if (!dropdownMenu || !dropdownButton) {
            debug.error('Dropdown elements not found!');
            return null;
        }
        
        try {
            debug.log('Setting up month dropdown from database...');
            const months = await this.getAvailableMonthsFromDb();
            debug.log('Months from database:', months);
            
            let menuHtml = '';
            let selectedMonth = null;
            
            // If no months in database, keep dropdown blank
            if (months.length === 0) {
                debug.log('No months found in database, keeping dropdown blank');
                menuHtml = '<li><a class="dropdown-item disabled" href="#">No data available</a></li>';
                dropdownButton.innerHTML = '<i class="fas fa-calendar me-1"></i>Select Month';
                dropdownButton.removeAttribute('data-month');
            } else {
                // Populate dropdown with months from database
                months.forEach(month => {
                    menuHtml += `
                        <li><a class="dropdown-item" href="#" data-month="${month.value}">${month.label}</a></li>
                    `;
                });
                
                // Set default to first available month
                selectedMonth = months[0].value;
                const defaultMonthLabel = months[0].label;
                debug.log('Setting default month to:', selectedMonth, 'label:', defaultMonthLabel);
                dropdownButton.innerHTML = `<i class="fas fa-calendar me-1"></i>${defaultMonthLabel}`;
                dropdownButton.setAttribute('data-month', selectedMonth);
            }
            
            dropdownMenu.innerHTML = menuHtml;
            
            // Add event listeners to dropdown items
            const dropdownItems = dropdownMenu.querySelectorAll('.dropdown-item:not(.disabled)');
            dropdownItems.forEach(item => {
                item.addEventListener('click', (e) => {
                    e.preventDefault();
                    const selectedMonth = e.target.getAttribute('data-month');
                    debug.log('Month selected from dropdown:', selectedMonth);
                    this.handleMonthChange(selectedMonth);
                    dropdownButton.innerHTML = `<i class="fas fa-calendar me-1"></i>${e.target.textContent}`;
                    dropdownButton.setAttribute('data-month', selectedMonth);
                });
            });
            
            return selectedMonth;
            
        } catch (error) {
            debug.error('Error setting up month dropdown:', error);
            // On error, keep dropdown blank
            dropdownMenu.innerHTML = '<li><a class="dropdown-item disabled" href="#">Error loading months</a></li>';
            dropdownButton.innerHTML = '<i class="fas fa-calendar me-1"></i>Select Month';
            return null;
        }
    }


    async setupUserDropdown() {
        debug.log('=== setupUserDropdown() called ===');
        const dropdownMenu = document.getElementById('userDropdownMenu');
        const dropdownButton = document.getElementById('userDropdown');
        
        if (!dropdownMenu || !dropdownButton) {
            debug.error('User dropdown elements not found!');
            return;
        }
        
        try {
            debug.log('Setting up user dropdown from dashboard members...');
            const users = await this.getDashboardUsers();
            debug.log('Dashboard users:', users);
            
            let menuHtml = '';
            
            // Add "All Users" option
            menuHtml += `
                <li><a class="dropdown-item active" href="#" data-user-id="all">All Users</a></li>
                <li><hr class="dropdown-divider"></li>
            `;
            
            // Populate dropdown with dashboard users
            users.forEach(user => {
                menuHtml += `
                    <li><a class="dropdown-item" href="#" data-user-id="${user.id}">${user.name}</a></li>
                `;
            });
            
            dropdownMenu.innerHTML = menuHtml;
            
            // Add event listeners to dropdown items
            const dropdownItems = dropdownMenu.querySelectorAll('.dropdown-item');
            dropdownItems.forEach(item => {
                item.addEventListener('click', (e) => {
                    e.preventDefault();
                    
                    // Remove active class from all items
                    dropdownItems.forEach(i => i.classList.remove('active'));
                    // Add active class to clicked item
                    e.target.classList.add('active');
                    
                    const selectedUserId = e.target.getAttribute('data-user-id');
                    const selectedUserName = e.target.textContent;
                    debug.log('User selected from dropdown:', selectedUserId, selectedUserName);
                    
                    this.handleUserChange(selectedUserId);
                    dropdownButton.innerHTML = `<i class="fas fa-user me-1"></i>${selectedUserName}`;
                });
            });
            
        } catch (error) {
            debug.error('Error setting up user dropdown:', error);
            // On error, keep dropdown with default option
            dropdownMenu.innerHTML = '<li><a class="dropdown-item active" href="#" data-user-id="all">All Users</a></li>';
        }
    }

    async getDashboardUsers() {
        try {
            // Fetch dashboard members from the API
            const response = await fetch(`/api/dashboard/${this.dashboardId}/members`);
            if (!response.ok) {
                throw new Error('Failed to fetch dashboard members');
            }
            
            const members = await response.json();
            debug.log('Dashboard members from API:', members);
            
            // Extract unique users from members
            const users = [];
            const seenUserIds = new Set();
            
            members.forEach(member => {
                if (member.user && !seenUserIds.has(member.user.id)) {
                    users.push({
                        id: member.user.id,
                        name: member.user.name
                    });
                    seenUserIds.add(member.user.id);
                }
            });
            
            debug.log('Unique users:', users);
            return users;
            
        } catch (error) {
            debug.error('Error getting dashboard users:', error);
            // Fallback: return current user only
            return [{
                id: window.currentUserId || 1,
                name: window.currentUserName || 'Current User'
            }];
        }
    }

    handleUserChange(selectedUserId) {
        debug.log('Selected user:', selectedUserId);
        // Refresh the table with the selected user filter
        const selectedMonth = this.getSelectedMonthFromDropdown();
        this.refreshMonthlyData(selectedMonth, selectedUserId);
        Utils.showNotification(`Showing data for ${selectedUserId === 'all' ? 'all users' : 'selected user'}`, 'info');
    }

    async getAvailableMonthsFromDb() {
        try {
            debug.log('Fetching expenses from API for dashboard:', this.dashboardId);
            const expenses = await ApiClient.expenses.get(this.dashboardId);
            debug.log('Raw expenses from API:', expenses);
            
            // Extract unique months from expenses
            const availableMonths = new Set();
            expenses.forEach(expense => {
                debug.log('Processing expense:', expense);
                if (expense.date) {
                    const month = expense.date.substring(0, 7); // YYYY-MM
                    debug.log('Extracted month:', month, 'from date:', expense.date);
                    availableMonths.add(month);
                }
            });
            
            debug.log('Available months set:', availableMonths);
            
            // Convert to array and sort (newest first)
            const months = Array.from(availableMonths)
                .sort()
                .reverse()
                .map(month => {
                    // Parse the month string correctly (YYYY-MM format)
                    const [year, monthNum] = month.split('-');
                    // Use UTC to avoid timezone issues
                    const date = new Date(Date.UTC(parseInt(year), parseInt(monthNum) - 1, 1));
                    const label = date.toLocaleDateString('en-US', { 
                        year: 'numeric', 
                        month: 'long',
                        timeZone: 'UTC' 
                    });
                    debug.log('Month object:', { value: month, label, year, monthNum, date: date.toString() });
                    return { value: month, label };
                });
            
            debug.log('Final months array:', months);
            return months;
        } catch (error) {
            debug.error('Error getting months from database:', error);
            return [];
        }
    }

    handleMonthChange(selectedMonth) {
        debug.log('Selected month:', selectedMonth);
        // Clear the current table and reload with data for the selected month
        if (this.monthlyTable) {
            // Clear the table first - use loadData with empty array
            this.monthlyTable.loadData([]);
            debug.log('clearing monthly table - loadData([]) called');
        }
        
        // Load data for the selected month
        this.refreshMonthlyData(selectedMonth);
        Utils.showNotification(`Showing data for ${selectedMonth}`, 'info');
    }

    async handleRowRemoval(selection) {
        debug.log('handleRowRemoval called with selection:', selection);
        
        try {
            const selectedMonth = this.getSelectedMonthFromDropdown();
            if (!selectedMonth) {
                Utils.showNotification('No month selected', 'warning');
                return;
            }

            if (!this.monthlyTable) {
                Utils.showNotification('Table not ready', 'warning');
                return;
            }

            // Collect all selected rows (support multi-select ranges)
            const rowsToDelete = new Set();
            const ranges = Array.isArray(selection) ? selection : [selection];
            ranges.forEach(range => {
                const startRow = range.start ? range.start.row : range.row;
                const endRow = range.end ? range.end.row : range.row;
                const from = Math.min(startRow, endRow);
                const to = Math.max(startRow, endRow);
                for (let r = from; r <= to; r++) {
                    rowsToDelete.add(r);
                }
            });

            if (rowsToDelete.size === 0) {
                Utils.showNotification('No rows selected', 'info');
                return;
            }

            // Delete expenses and remove rows (process bottom-up to avoid index shift)
            const sortedRows = Array.from(rowsToDelete).sort((a, b) => b - a);
            let deletedCount = 0;
            for (const rowIndex of sortedRows) {
                const rowData = this.monthlyTable.getDataAtRow(rowIndex);
                if (!rowData) continue;
                const expenseId = rowData[rowData.length - 1];
                debug.log('Attempting delete for row', rowIndex, 'expenseId', expenseId, 'rowData', rowData);
                if (!expenseId) {
                    debug.warn('Skipping row with no expense ID at index', rowIndex);
                    continue;
                }
                await ApiClient.expenses.delete(this.dashboardId, expenseId);
                this.monthlyTable.alter('remove_row', rowIndex);
                deletedCount += 1;
            }

            if (deletedCount > 0) {
                Utils.showNotification(`Deleted ${deletedCount} expense${deletedCount > 1 ? 's' : ''}`, 'success');
                const currentTableData = this.monthlyTable.getData();
                this.updateCategoryBreakdownFromTableData(currentTableData);
                await this.initYearlyTable(); // keep yearly view in sync
            } else {
                Utils.showNotification('No expenses deleted', 'info');
            }
        } catch (error) {
            debug.error('Error handling row removal:', error);
            
            // Handle 403 Forbidden errors specifically
            if (error.status === 403) {
                Utils.showNotification(error.message || 'You do not have permission to delete this expense', 'danger');
            } else {
                Utils.showNotification('Error deleting expense: ' + error.message, 'danger');
            }
        }
    }

    async refreshMonthlyData(month = null, userId = null) {
        try {
            debug.log('refreshMonthlyData called with month:', month, 'and user:', userId);
            const expenses = await ApiClient.expenses.get(this.dashboardId);
            debug.log('Fetched expenses from API:', expenses);
            
            // Filter by month if specified
            let filteredExpenses = expenses;
            if (month) {
                debug.log('Filtering for month:', month);
                filteredExpenses = expenses.filter(expense => {
                    const expenseMonth = expense.date.substring(0, 7); // YYYY-MM
                    return expenseMonth === month;
                });
            }
            
            // Filter by user if specified (not "all")
            if (userId && userId !== 'all') {
                debug.log('Filtering for user:', userId);
                filteredExpenses = filteredExpenses.filter(expense => {
                    return expense.user_id == userId;
                });
            }
            
            debug.log('Filtered expenses for month', month, 'and user', userId, ':', filteredExpenses);
            
            // Update Handsontable with new data
            if (this.monthlyTable) {
                // Convert to object format that Handsontable expects
                const tableData = filteredExpenses.map(expense => ({
                    id: expense.id,
                    date: expense.date,
                    description: expense.description,
                    amount: expense.amount,
                    category: expense.category,
                    user_name: expense.user_name
                }));
                debug.log('Loading table data into Handsontable:', tableData);
                this.monthlyTable.loadData(tableData);
            }

            // Update category breakdown
            this.updateCategoryBreakdown(filteredExpenses);
        } catch (error) {
            debug.error('Error refreshing monthly data:', error);
        }
    }

    updateCategoryBreakdown(expenses) {
        const pivotContainer = document.getElementById('categoryPivotTable');
        if (!pivotContainer) return;

        // Calculate category totals
        const categoryTotals = {};
        let totalAmount = 0;
        
        expenses.forEach(expense => {
            if (!categoryTotals[expense.category]) {
                categoryTotals[expense.category] = 0;
            }
            categoryTotals[expense.category] += expense.amount;
            totalAmount += expense.amount;
        });

        // Create HTML for category breakdown
        let html = '<div class="list-group list-group-flush">';
        
        // Add category rows
        Object.entries(categoryTotals)
            .sort(([,a], [,b]) => b - a)
            .forEach(([category, total]) => {
                html += `
                    <div class="list-group-item d-flex justify-content-between align-items-center">
                        <span class="text-capitalize">${category}</span>
                        <span class="badge bg-primary rounded-pill">${Utils.formatCurrency(total)}</span>
                    </div>
                `;
            });
        
        // Add total row
        html += `
            <div class="list-group-item category-total d-flex justify-content-between align-items-center">
                <span class="fw-bold">Total</span>
                <span class="badge bg-primary rounded-pill">${Utils.formatCurrency(totalAmount)}</span>
            </div>
        `;
        
        html += '</div>';

        pivotContainer.innerHTML = html;
    }

    updateCategoryBreakdownFromTableData(tableData) {
        const pivotContainer = document.getElementById('categoryPivotTable');
        if (!pivotContainer) return;

        // Calculate category totals from table data (array format from Handsontable)
        const categoryTotals = {};
        let totalAmount = 0;

        debug.log('=== DEBUG: Processing table data for category breakdown ===');
        debug.log('Table data type:', typeof tableData);
        debug.log('Table data length:', tableData.length);
        debug.log('First row sample:', tableData[0]);

        tableData.forEach((row, index) => {
            if (row && Array.isArray(row) && row.length >= 4) {
                // Handsontable data is in array format: [date, category, amount, description, user_name, id]
                const category = row[1]; // Column 1 is category
                const amount = parseFloat(row[2]) || 0; // Column 2 is amount
                
                debug.log(`Row ${index}: category="${category}", amount=${amount}`);
                
                if (category && amount > 0) {
                    if (!categoryTotals[category]) {
                        categoryTotals[category] = 0;
                    }
                    categoryTotals[category] += amount;
                    totalAmount += amount;
                }
            }
        });

        debug.log('Category totals:', categoryTotals);
        debug.log('Total amount:', totalAmount);
        
        // Create HTML for category breakdown
        let html = '<div class="list-group list-group-flush">';
        
        // Add category rows
        Object.entries(categoryTotals)
            .sort(([,a], [,b]) => b - a)
            .forEach(([category, total]) => {
                html += `
                    <div class="list-group-item d-flex justify-content-between align-items-center">
                        <span class="text-capitalize">${category}</span>
                        <span class="badge bg-primary rounded-pill">${Utils.formatCurrency(total)}</span>
                    </div>
                `;
            });
        
        // Add total row
        html += `
            <div class="list-group-item category-total d-flex justify-content-between align-items-center">
                <span class="fw-bold">Total</span>
                <span class="badge bg-primary rounded-pill">${Utils.formatCurrency(totalAmount)}</span>
            </div>
        `;
        
        html += '</div>';

        pivotContainer.innerHTML = html;
    }

    async initYearlyTable() {
        const table = document.getElementById('yearlyTable');
        if (!table) return;

        try {
            // Fetch all expenses from the API
            const expenses = await ApiClient.expenses.get(this.dashboardId);
            
            // Process data into yearly pivot format
            const yearlyData = this.processYearlyPivotData(expenses);
            
            // Generate HTML for the yearly table
            this.renderYearlyTable(yearlyData);
            
        } catch (error) {
            debug.error('Error initializing yearly table:', error);
            // Fallback to sample data if API fails
            this.renderYearlyTable(this.getSampleYearlyData());
        }
    }

    processYearlyPivotData(expenses) {
        const yearlyData = {};
        
        // Define all months for consistent columns
        const monthNames = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
        
        // Process each expense
        expenses.forEach(expense => {
            if (!expense.date || !expense.category || !expense.amount) return;
            
            // Parse date safely - extract YYYY-MM from the date string directly
            // This avoids timezone issues with JavaScript Date constructor
            const dateParts = expense.date.split('-');
            if (dateParts.length < 2) return;
            
            const year = parseInt(dateParts[0]);
            const month = parseInt(dateParts[1]) - 1; // Convert to 0-based month
            const monthName = monthNames[month];
            const category = expense.category.toLowerCase();
            
            // Initialize year if not exists
            if (!yearlyData[year]) {
                yearlyData[year] = {};
                // Initialize all categories with all months set to 0
                const categories = ['car', 'gas', 'grocery', 'home exp', 'home setup', 'gym', 'hospital', 'misc', 'rent', 'mortgage', 'restaurant', 'service', 'shopping', 'transport', 'utility', 'vacation'];
                categories.forEach(cat => {
                    yearlyData[year][cat] = {};
                    monthNames.forEach(month => {
                        yearlyData[year][cat][month] = 0;
                    });
                });
            }
            
            // Add amount to the appropriate category and month
            if (yearlyData[year][category] && yearlyData[year][category][monthName] !== undefined) {
                yearlyData[year][category][monthName] += expense.amount;
            }
        });
        
        return yearlyData;
    }

    renderYearlyTable(yearlyData) {
        const table = document.getElementById('yearlyTable');
        if (!table) return;
        
        const monthNames = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
        const monthHeaders = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        const categories = ['car', 'gas', 'grocery', 'home exp', 'home setup', 'gym', 'hospital', 'misc', 'rent', 'mortgage', 'restaurant', 'service', 'shopping', 'transport', 'utility', 'vacation'];
        
        let html = '';
        
        // Sort years in descending order
        const years = Object.keys(yearlyData).sort((a, b) => b - a);
        
        years.forEach(year => {
            // Calculate totals for each month and overall
            const monthlyTotals = {};
            let yearlyTotal = 0;
            
            monthNames.forEach(month => {
                monthlyTotals[month] = 0;
                categories.forEach(category => {
                    if (yearlyData[year][category] && yearlyData[year][category][month]) {
                        monthlyTotals[month] += yearlyData[year][category][month];
                    }
                });
                yearlyTotal += monthlyTotals[month];
            });
            
            // Year header
            html += `
                <div class="year-section mb-4">
                    <h5 class="text-primary mb-3">${year}</h5>
                    <div class="table-responsive yearly-pivot-scroll">
                        <div class="yearly-pivot-grid">
                            <div class="yearly-pivot-cell is-header sticky-category">Category</div>
                            ${monthHeaders.map(month => `<div class="yearly-pivot-cell is-header is-number">${month}</div>`).join('')}
                            <div class="yearly-pivot-cell is-header is-number sticky-total">Total</div>
            `;
            
            // Category rows
            categories.forEach(category => {
                const rowData = yearlyData[year][category];
                if (rowData) {
                    let categoryTotal = 0;
                    const monthCells = monthNames.map(month => {
                        const amount = rowData[month] || 0;
                        categoryTotal += amount;
                        return `<div class="yearly-pivot-cell is-number">${amount > 0 ? Utils.formatCurrency(amount) : '-'}</div>`;
                    }).join('');
                    
                    html += `
                            <div class="yearly-pivot-cell is-row-header sticky-category">${category}</div>
                            ${monthCells}
                            <div class="yearly-pivot-cell is-number sticky-total">${categoryTotal > 0 ? Utils.formatCurrency(categoryTotal) : '-'}</div>
                    `;
                }
            });
            
            // Monthly totals row
            html += `
                            <div class="yearly-pivot-cell is-monthly-total sticky-category">Monthly Total</div>
                            ${monthNames.map(month => {
                                const amount = monthlyTotals[month] || 0;
                                return `<div class="yearly-pivot-cell is-number is-monthly-total">${amount > 0 ? Utils.formatCurrency(amount) : '-'}</div>`;
                            }).join('')}
                            <div class="yearly-pivot-cell is-number is-monthly-total sticky-total">${yearlyTotal > 0 ? Utils.formatCurrency(yearlyTotal) : '-'}</div>
            `;
            
            html += `
                        </div>
                    </div>
                </div>
            `;
        });
        
        table.innerHTML = html;
        
        // If no data, show message
        if (years.length === 0) {
            table.innerHTML = `
                <div class="alert alert-info">
                    <i class="fas fa-info-circle me-2"></i>
                    No expense data available for yearly overview.
                </div>
            `;
        }
    }

    getSampleYearlyData() {
        // Sample data for testing when API is not available
        return {
            2024: {
                car: { jan: 100, feb: 100, mar: 100, apr: 100, may: 100, jun: 100, jul: 100, aug: 100, sep: 100, oct: 100, nov: 100, dec: 100 },
                gas: { jan: 50, feb: 200, mar: 300, apr: 150, may: 100, jun: 75, jul: 80, aug: 90, sep: 120, oct: 110, nov: 95, dec: 50 },
                grocery: { jan: 500, feb: 250, mar: 50, apr: 300, may: 400, jun: 350, jul: 320, aug: 280, sep: 310, oct: 290, nov: 330, dec: 600 },
                restaurant: { jan: 265, feb: 180, mar: 220, apr: 190, may: 210, jun: 195, jul: 205, aug: 215, sep: 225, oct: 235, nov: 245, dec: 255 },
                utility: { jan: 150, feb: 145, mar: 160, apr: 155, may: 165, jun: 170, jul: 175, aug: 180, sep: 185, oct: 190, nov: 195, dec: 200 },
                misc: { jan: 75, feb: 80, mar: 65, apr: 90, may: 85, jun: 95, jul: 100, aug: 110, sep: 105, oct: 115, nov: 125, dec: 135 }
            },
            2025: {
                car: { jan: 120, feb: 120, mar: 120, apr: 120, may: 120, jun: 120, jul: 120, aug: 120, sep: 120, oct: 120, nov: 120, dec: 120 },
                gas: { jan: 60, feb: 220, mar: 320, apr: 160, may: 110, jun: 85, jul: 90, aug: 100, sep: 130, oct: 120, nov: 105, dec: 60 },
                grocery: { jan: 520, feb: 270, mar: 60, apr: 320, may: 420, jun: 370, jul: 340, aug: 300, sep: 330, oct: 310, nov: 350, dec: 620 },
                restaurant: { jan: 275, feb: 190, mar: 230, apr: 200, may: 220, jun: 205, jul: 215, aug: 225, sep: 235, oct: 245, nov: 255, dec: 265 },
                utility: { jan: 160, feb: 155, mar: 170, apr: 165, may: 175, jun: 180, jul: 185, aug: 190, sep: 195, oct: 200, nov: 205, dec: 210 },
                misc: { jan: 85, feb: 90, mar: 75, apr: 100, may: 95, jun: 105, jul: 110, aug: 120, sep: 115, oct: 125, nov: 135, dec: 145 }
            }
        };
    }

    async updateMonthlyChanges(rowId, rowData) {
        try {
            if (!rowId) {
                debug.error('No row ID provided for update');
                return;
            }
            
            if (!rowData || !rowData.date || !rowData.description || !rowData.amount) {
                debug.error('Invalid row data for update:', rowData);
                return;
            }
            
            const expenseData = {
                date: rowData.date,
                description: rowData.description,
                amount: parseFloat(rowData.amount),
                category: rowData.category || 'misc'
            };
            
            // Check if this is a new row (ID = 'new') or an existing row
            if (rowId === 'new') {
                // Create new expense in database
                const result = await ApiClient.expenses.create(this.dashboardId, expenseData);
                debug.log('New expense created:', result);
                
                // Refresh the table to get the new expense with its real ID
                const selectedMonth = this.getSelectedMonthFromDropdown();
                if (selectedMonth) {
                    await this.refreshMonthlyData(selectedMonth);
                }
                
                Utils.showNotification('New expense saved successfully', 'success');
            } else {
                // Update existing expense using PUT
                await ApiClient.expenses.update(this.dashboardId, rowId, expenseData);
                
                // Update the category breakdown immediately from the current table data
                const currentTableData = this.monthlyTable.getData();
                this.updateCategoryBreakdownFromTableData(currentTableData);
                
                // Refresh yearly table to reflect the changes
                await this.initYearlyTable();
                
                Utils.showNotification('Expense updated successfully', 'success');
            }
            
        } catch (error) {
            debug.error('Error updating monthly changes:', error);
            
            // Handle 403 Forbidden errors specifically
            if (error.status === 403) {
                Utils.showNotification(error.message || 'You do not have permission to edit this expense', 'danger');
            } else {
                Utils.showNotification('Error saving expense: ' + error.message, 'danger');
            }
        }
    }
    
    async handleRowAddition(selection) {
        debug.log('handleRowAddition called with selection:', selection);
        
        try {
            const selectedMonth = this.getSelectedMonthFromDropdown();
            if (!selectedMonth) {
                Utils.showNotification('No month selected', 'warning');
                return;
            }
            
            // Get the row index where the new row should be added
            const rowIndex = selection[0].start.row;
            debug.log('Adding new row at index:', rowIndex);
            
            // Create a temporary local row with placeholder values
            const newRow = {
                date: new Date().toISOString().split('T')[0], // Today's date
                description: 'New Expense',
                amount: 0.00,
                category: 'misc',
                user_name: window.currentUserName || 'Current User',
                id: 'new' // Temporary ID for new rows
            };
            
            // Get current data and insert new row
            const currentData = this.monthlyTable.getData();
            const newData = [
                ...currentData.slice(0, rowIndex),
                [newRow.date, newRow.category, newRow.amount, newRow.description, newRow.user_name, newRow.id],
                ...currentData.slice(rowIndex)
            ];
            
            // Update the table with new data
            this.monthlyTable.loadData(newData);
            
            // Add a save button for this new row
            this.addSaveButtonToRow(rowIndex);
            
            Utils.showNotification('New row added. Fill out the details and click the save button when ready.', 'info');
            
        } catch (error) {
            debug.error('Error handling row addition:', error);
            Utils.showNotification('Error adding new row', 'danger');
        }
    }
    
    addSaveButtonToRow(rowIndex) {
        // Desktop/tablet only: show inline save buttons; skip on touch/mobile since we have top-level action
        if (this.isTouchDevice) {
            return;
        }
        // Create a save button element
        const saveButton = document.createElement('button');
        saveButton.className = 'btn btn-sm btn-success save-row-btn';
        saveButton.innerHTML = '<i class="fas fa-save"></i>';
        saveButton.style.marginLeft = '5px';
        saveButton.style.marginTop = '5px';
        saveButton.style.width = '30px'; // Fixed width for consistency
        saveButton.style.height = '25px'; // Fixed height for consistency
        saveButton.style.padding = '0'; // Remove padding for compact look
        saveButton.title = 'Save this row'; // Tooltip for clarity
        
        // Add click event to save the row
        saveButton.addEventListener('click', async () => {
            await this.saveNewRow(rowIndex);
        });
        
        // Find the row header cell and append the save button
        const rowHeader = this.monthlyTable.getCell(rowIndex, -1, true); // Get row header cell
        if (rowHeader) {
            rowHeader.appendChild(saveButton);
        }
    }
    
    async saveNewRow(rowIndex) {
        try {
            // Get the row data
            const rowData = this.monthlyTable.getDataAtRow(rowIndex);
            debug.log('Saving new row data:', rowData);
            
            // Extract expense data from row
            const expenseData = {
                date: rowData[0],
                description: rowData[3],
                amount: parseFloat(rowData[2]) || 0,
                category: rowData[1] || 'misc'
            };
            
            // Validate required fields
            if (!expenseData.date || !expenseData.description || expenseData.amount <= 0) {
                Utils.showNotification('Please fill out all required fields (Date, Description, Amount > 0)', 'warning');
                return;
            }
            
            // Create new expense in database
            const result = await ApiClient.expenses.create(this.dashboardId, expenseData);
            debug.log('New expense created:', result);
            
            // Remove the save button
            this.removeSaveButtonFromRow(rowIndex);
            
            // Refresh the table to get the new expense with its real ID
            const selectedMonth = this.getSelectedMonthFromDropdown();
            if (selectedMonth) {
                await this.refreshMonthlyData(selectedMonth);
            }
            
            Utils.showNotification('New expense saved successfully', 'success');
            
        } catch (error) {
            debug.error('Error saving new row:', error);
            Utils.showNotification('Error saving expense: ' + error.message, 'danger');
        }
    }
    
    removeSaveButtonFromRow(rowIndex) {
        // Find and remove the save button from the row header
        const rowHeader = this.monthlyTable.getCell(rowIndex, -1, true);
        if (rowHeader) {
            const saveButton = rowHeader.querySelector('.save-row-btn');
            if (saveButton) {
                saveButton.remove();
            }
        }
    }
    
    async refreshYearlyData() {
        try {
            // In production, this would fetch aggregated yearly data
            debug.log('Refreshing yearly data');
        } catch (error) {
            debug.error('Error refreshing yearly data:', error);
        }
    }

    resetUploadUI() {
        const optionCards = document.querySelectorAll('.option-card');
        const sheetsPasteArea = document.getElementById('sheetsPasteArea');
        const aiUploadArea = document.getElementById('aiUploadArea');
        const processingArea = document.getElementById('processingArea');
        const csvPreviewArea = document.getElementById('csvPreviewArea');
        
        // Reset all UI elements
        optionCards.forEach(card => {
            card.classList.remove('d-none');
        });
        if (sheetsPasteArea) sheetsPasteArea.classList.add('d-none');
        if (aiUploadArea) aiUploadArea.classList.add('d-none');
        if (processingArea) processingArea.classList.add('d-none');
        if (csvPreviewArea) csvPreviewArea.classList.add('d-none');
        
        // Clear file inputs
        const sheetsPasteText = document.getElementById('sheetsPasteText');
        const aiFileInput = document.getElementById('aiFileInput');
        
        if (sheetsPasteText) sheetsPasteText.value = '';
        if (aiFileInput) aiFileInput.value = '';
        
        // Clear current data
        this.currentFile = null;
        this.currentFileType = null;
        this.currentCsvData = null;
        this.currentSessionId = null;
        this.currentSource = null;
    }
}

// Edit Mode Settings functionality
function initializeEditModeSettings() {
    const saveEditModeBtn = document.getElementById('saveEditMode');
    if (saveEditModeBtn) {
        saveEditModeBtn.addEventListener('click', saveEditMode);
        loadCurrentEditMode();
    }
}

async function loadCurrentEditMode() {
    try {
        const dashboardId = window.location.pathname.split('/').pop();
        const response = await fetch(`/api/dashboard/${dashboardId}/settings`);
        
        if (response.ok) {
            const settings = await response.json();
            const editMode = settings.edit_mode || 'private';
            
            // Set the radio button based on current setting
            if (editMode === 'public') {
                document.getElementById('publicMode').checked = true;
            } else {
                document.getElementById('privateMode').checked = true;
            }
        }
    } catch (error) {
        debug.error('Error loading edit mode settings:', error);
        // Default to private mode on error
        document.getElementById('privateMode').checked = true;
    }
}

async function saveEditMode() {
    const privateModeRadio = document.getElementById('privateMode');
    const publicModeRadio = document.getElementById('publicMode');
    const saveBtn = document.getElementById('saveEditMode');
    
    let editMode = 'private';
    if (publicModeRadio.checked) {
        editMode = 'public';
    }
    
    try {
        const dashboardId = window.location.pathname.split('/').pop();
        const response = await fetch(`/api/dashboard/${dashboardId}/settings`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({
                edit_mode: editMode
            })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            Utils.showNotification(`Edit mode set to ${editMode} mode`, 'success');
        } else {
            Utils.showNotification(result.error || 'Failed to save settings', 'danger');
        }
    } catch (error) {
        debug.error('Error saving edit mode:', error);
        Utils.showNotification('Network error: ' + error.message, 'danger');
    }
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', function() {
    // Extract dashboard ID from URL or data attribute
    const dashboardId = window.location.pathname.split('/').pop();
    if (dashboardId && !isNaN(dashboardId)) {
        window.dashboardManager = new DashboardManager(dashboardId);
    }
    
    // Initialize edit mode settings
    initializeEditModeSettings();
});
