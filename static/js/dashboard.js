// Dashboard-specific JavaScript functionality

class DashboardManager {
    constructor(dashboardId) {
        this.dashboardId = dashboardId;
        this.currentSessionId = null;
        this.currentCsvData = null;
        this.init();
    }

    init() {
        this.setupPdfProcessing();
        this.setupAiChat();
        this.setupTableEditors();
        this.setupEventListeners();
    }

    setupPdfProcessing() {
        // Setup two option layout
        this.setupOptionSelection();
        
        // Setup Google Sheets paste functionality
        const processSheetsBtn = document.getElementById('processSheetsData');
        const sheetsPasteText = document.getElementById('sheetsPasteText');
        const cancelSheetsBtn = document.getElementById('cancelSheets');
        
        if (processSheetsBtn && sheetsPasteText) {
            processSheetsBtn.addEventListener('click', this.handleSheetsPaste.bind(this));
            sheetsPasteText.addEventListener('paste', this.handleSheetsPaste.bind(this));
        }
        
        if (cancelSheetsBtn) {
            cancelSheetsBtn.addEventListener('click', () => this.cancelOption('sheets'));
        }
        
        // Setup AI file upload
        const aiFileInput = document.getElementById('aiFileInput');
        const cancelAIBtn = document.getElementById('cancelAI');
        
        if (aiFileInput) {
            aiFileInput.addEventListener('change', this.handleAIUpload.bind(this));
        }
        
        if (cancelAIBtn) {
            cancelAIBtn.addEventListener('click', () => this.cancelOption('ai'));
        }
    }
    
    setupOptionSelection() {
        const optionCards = document.querySelectorAll('.option-card');
        optionCards.forEach(card => {
            const button = card.querySelector('button');
            button.addEventListener('click', (e) => {
                e.stopPropagation();
                const option = card.getAttribute('data-option');
                this.selectOption(option);
            });
            
            // Also allow clicking the entire card
            card.addEventListener('click', (e) => {
                if (e.target.tagName !== 'BUTTON') {
                    const option = card.getAttribute('data-option');
                    this.selectOption(option);
                }
            });
        });
    }
    
    selectOption(option) {
        console.log('Selected option:', option);
        
        // Hide all option cards
        const optionCards = document.querySelectorAll('.option-card');
        optionCards.forEach(card => {
            card.classList.add('d-none');
        });
        
        // Show the selected option interface
        if (option === 'sheets') {
            this.showSheetsInterface();
        } else if (option === 'ai') {
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
        // Hide the current option interface
        if (option === 'sheets') {
            const sheetsPasteArea = document.getElementById('sheetsPasteArea');
            sheetsPasteArea.classList.add('d-none');
            const sheetsPasteText = document.getElementById('sheetsPasteText');
            sheetsPasteText.value = '';
        } else if (option === 'ai') {
            const aiUploadArea = document.getElementById('aiUploadArea');
            aiUploadArea.classList.add('d-none');
            const aiFileInput = document.getElementById('aiFileInput');
            aiFileInput.value = '';
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
    }
    
    async handleAIUpload(event) {
        const file = event.target.files[0];
        if (!file) {
            // User clicked the AI card but hasn't selected a file yet
            // Just show the upload interface and wait for file selection
            return;
        }
        
        const fileType = this.detectFileType(file);
        console.log('AI processing - File type detected:', fileType);
        
        if (!fileType) {
            Utils.showNotification('Unsupported file type. Please upload CSV, Excel, or PDF files only.', 'warning');
            return;
        }
        
        // Clear chat box when new file is uploaded
        this.clearAiChat();
        
        // Clear localStorage for this dashboard when new file is uploaded
        const localStorageKey = `pdf_extraction_${this.dashboardId}`;
        localStorage.removeItem(localStorageKey);
        console.log('Cleared localStorage for new file upload:', localStorageKey);
        
        // Store file info for later processing
        this.currentFile = file;
        this.currentFileType = fileType;
        
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
            
            // Add CSV data to chat context
            this.addAiChatMessage('assistant', `I've loaded your CSV file. You can now ask me to process this data. For example: "Filter only transactions above $50", "Categorize expenses", or "Remove duplicate entries".`);
            
            // Show CSV preview
            this.showCsvPreview(csvText);
            
        } catch (error) {
            console.error('CSV processing error:', error);
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
    
    
    async processPdfWithAI(file) {
        try {
            const processingArea = document.getElementById('processingArea');
            const progressBar = processingArea.querySelector('.progress-bar');

            // Show processing UI
            processingArea.classList.remove('d-none');

            // Convert PDF to base64 for AI processing - use a safer method
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
            
            // Show processing status
            progressBar.style.width = '50%';
            
            // Send PDF to AI for extraction - use direct fetch to avoid argument issues
            const response = await fetch(`/api/dashboard/${this.dashboardId}/ai/extract-pdf`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    pdf_data: base64Pdf,
                    filename: file.name
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
                this.showCsvPreview(result.csv_data);
                Utils.showNotification('PDF processed successfully using AI', 'success');
            } else {
                throw new Error('No CSV data returned from AI');
            }
            
        } catch (error) {
            console.error('PDF processing error:', error);
            Utils.showNotification('Error processing PDF with AI. Please try again or use Google Sheets copy instead.', 'danger');
            this.resetUploadUI();
        }
    }
    
    
    readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = (e) => reject(e);
            reader.readAsText(file);
        });
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
        }
    }
    
    addAiChatMessage(role, content) {
        const chatMessages = document.getElementById('aiChatMessages');
        const messageDiv = document.createElement('div');
        messageDiv.className = `chat-message ${role} mb-2`;
        messageDiv.innerHTML = `<strong>${role === 'user' ? 'You' : 'AI Assistant'}:</strong> ${content}`;
        chatMessages.appendChild(messageDiv);
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
            console.error('AI chat processing error:', error);
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
                    console.log('Using existing extraction_id from localStorage:', extractionId);
                } else {
                    // Different file, clear old state
                    localStorage.removeItem(localStorageKey);
                    console.log('New file detected, clearing old extraction state');
                }
            }
            
            if (!extractionId) {
                // Show processing status in chat
                this.addAiChatMessage('assistant', 'Processing PDF extraction...');
                
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
                
                // Step 1: Extract PDF text using the new endpoint (no AI processing)
                const extractResponse = await fetch(`/api/dashboard/${this.dashboardId}/ai/extract-pdf`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        pdf_data: base64Pdf,
                        filename: file.name
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
                    dashboard_id: this.dashboardId
                }));
                
                console.log('PDF extraction completed, stored extraction_id:', extractionId);
            } else {
                console.log('Using existing extraction_id for chat:', extractionId);
            }
            
            // Step 2: Process chat with the extraction_id
            const chatResponse = await fetch(`/api/dashboard/${this.dashboardId}/ai/process-chat`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
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
            console.error('PDF conversational processing error:', error);
            this.addAiChatMessage('assistant', 'Error processing PDF with AI. Please try again.');
            this.resetUploadUI();
        }
    }
    
    getConversationHistory() {
        const chatMessages = document.getElementById('aiChatMessages');
        const messages = chatMessages.querySelectorAll('.chat-message');
        const history = [];
        
        messages.forEach(message => {
            const role = message.classList.contains('user') ? 'user' : 'assistant';
            const content = message.textContent.replace(/^(You|AI Assistant):\s*/, '');
            history.push({
                role: role,
                content: content
            });
        });
        
        return history;
    }

    async processPdfWithPrompt(file, prompt) {
        try {
            const processingArea = document.getElementById('processingArea');
            const progressBar = processingArea.querySelector('.progress-bar');

            // Show processing UI
            processingArea.classList.remove('d-none');

            // Convert PDF to base64 for AI processing
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
            
            // Show processing status
            progressBar.style.width = '50%';
            
            // Send PDF to AI for extraction with prompt
            const response = await fetch(`/api/dashboard/${this.dashboardId}/ai/extract-pdf`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    pdf_data: base64Pdf,
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
                this.addAiChatMessage('assistant', 'I\'ve extracted the data from your PDF. Here\'s the processed CSV:');
                this.showCsvPreview(result.csv_data);
                Utils.showNotification('PDF processed successfully using AI', 'success');
            } else {
                throw new Error('No CSV data returned from AI');
            }
            
        } catch (error) {
            console.error('PDF processing error:', error);
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
            console.error('Excel processing error:', error);
            this.addAiChatMessage('assistant', 'Error processing Excel with AI. Please try again.');
            this.resetUploadUI();
        }
    }
    
    async processCsvWithPrompt(prompt) {
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
                this.showEditableCsvTable(response.processed_csv);
            }
            
        } catch (error) {
            console.error('AI processing error:', error);
            this.addAiChatMessage('assistant', 'Sorry, I encountered an error processing your request. Please try again.');
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
    }

    setupEventListeners() {
        // Tab change events
        const tabs = document.querySelectorAll('#dashboardTabs button[data-bs-toggle="tab"]');
        tabs.forEach(tab => {
            tab.addEventListener('shown.bs.tab', (event) => {
                const target = event.target.getAttribute('data-bs-target');
                if (target === '#monthly') {
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
                }
            });
        });
    }

    getSelectedMonthFromDropdown() {
        const dropdownButton = document.getElementById('monthDropdown');
        if (!dropdownButton) return null;
        
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

    async handlePdfUpload(event) {
        const file = event.target.files[0];
        if (!file || file.type !== 'application/pdf') {
            Utils.showNotification('Please select a valid PDF file', 'warning');
            return;
        }

        const processingArea = document.getElementById('processingArea');
        const progressBar = processingArea.querySelector('.progress-bar');

        // Show processing UI
        processingArea.classList.remove('d-none');

        try {
            // Convert PDF to base64 for AI processing
            const arrayBuffer = await file.arrayBuffer();
            const base64Pdf = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
            
            // Show processing status
            progressBar.style.width = '50%';
            
            // Send PDF to AI for extraction
            const response = await ApiClient.ai.extractFromPdf(this.dashboardId, base64Pdf, file.name);
            
            // Update progress
            progressBar.style.width = '100%';
            
            if (response.csv_data) {
                this.currentCsvData = response.csv_data;
                this.showCsvPreview(response.csv_data);
                Utils.showNotification('PDF processed successfully using AI', 'success');
            } else {
                throw new Error('No CSV data returned from AI');
            }
            
        } catch (error) {
            console.error('PDF processing error:', error);
            Utils.showNotification('Error processing PDF with AI. Please try again or use Google Sheets copy instead.', 'danger');
            this.resetUploadUI();
        }
    }

    async handleSheetsPaste(event) {
        let pastedData = '';
        
        if (event.type === 'paste') {
            // Get pasted data from clipboard
            pastedData = (event.clipboardData || window.clipboardData).getData('text');
        } else {
            // Get data from textarea
            const sheetsPasteArea = document.getElementById('sheetsPasteArea');
            pastedData = sheetsPasteArea.value.trim();
        }
        
        if (!pastedData) {
            Utils.showNotification('Please paste some data first', 'warning');
            return;
        }

        try {
            // Process Google Sheets data (tab-separated values)
            const csvData = this.convertSheetsToCsv(pastedData);
            this.currentCsvData = csvData;
            
            // Show CSV preview
            this.showCsvPreview(csvData);
            
            Utils.showNotification('Google Sheets data processed successfully', 'success');
        } catch (error) {
            console.error('Error processing Google Sheets data:', error);
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
                        category = cell;
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

    extractTablesFromText(text) {
        // Simple table extraction logic
        // This is a basic implementation - in production, you'd want more sophisticated parsing
        
        const lines = text.split('\n').filter(line => line.trim());
        const potentialTableRows = [];
        
        // Look for lines that might be table rows (contain numbers and consistent patterns)
        lines.forEach(line => {
            // Check if line contains date patterns and amounts
            const hasDate = /\d{1,2}\/\d{1,2}\/\d{2,4}/.test(line);
            const hasAmount = /\$\d+\.?\d*|USD\s*\d+\.?\d*/.test(line);
            const hasMultipleWords = line.trim().split(/\s+/).length >= 3;
            
            if ((hasDate || hasAmount) && hasMultipleWords) {
                potentialTableRows.push(line.trim());
            }
        });

        // Convert to CSV format
        if (potentialTableRows.length > 0) {
            const csvRows = ['Date,Description,Amount,Category'];
            
            potentialTableRows.forEach(row => {
                // Simple parsing - extract date, description, amount
                const dateMatch = row.match(/(\d{1,2}\/\d{1,2}\/\d{2,4})/);
                const amountMatch = row.match(/(\$\d+\.?\d*|USD\s*\d+\.?\d*)/);
                
                const date = dateMatch ? dateMatch[1] : '';
                const amount = amountMatch ? amountMatch[1].replace('USD', '').trim() : '';
                const description = row.replace(date || '', '').replace(amount || '', '').trim();
                
                if (date && amount && description) {
                    csvRows.push(`"${date}","${description}","${amount}",""`);
                }
            });
            
            return csvRows.join('\n');
        }
        
        // Fallback: return text as single column CSV
        return 'Description\n' + lines.map(line => `"${line}"`).join('\n');
    }

    showCsvPreview(csvData) {
        const processingArea = document.getElementById('processingArea');
        const csvPreviewArea = document.getElementById('csvPreviewArea');
        const previewTable = document.getElementById('csvPreviewTable');
        
        processingArea.classList.add('d-none');
        csvPreviewArea.classList.remove('d-none');
        
        // Parse CSV and create table preview
        const rows = csvData.split('\n');
        let tableHtml = '';
        
        rows.forEach((row, index) => {
            const cells = row.split(',').map(cell => cell.replace(/^"|"$/g, ''));
            tableHtml += '<tr>';
            cells.forEach(cell => {
                if (index === 0) {
                    tableHtml += `<th>${cell}</th>`;
                } else {
                    tableHtml += `<td>${cell}</td>`;
                }
            });
            tableHtml += '</tr>';
        });
        
        previewTable.innerHTML = tableHtml;
        
        // Setup edit button
        const editBtn = document.getElementById('editCsv');
        if (editBtn) {
            editBtn.addEventListener('click', () => {
                this.showEditableCsvTable(csvData);
            });
        }

        // Setup save data button
        const saveBtn = document.getElementById('saveCsv');
        if (saveBtn) {
            saveBtn.addEventListener('click', () => {
                this.saveCsvDataDirectly(csvData);
            });
        }
    }


    showEditableCsvTable(csvData) {
        const editableTableContainer = document.getElementById('editableCsvTable');
        if (!editableTableContainer) return;
        
        // Parse CSV data
        const rows = csvData.split('\n');
        const headers = rows[0].split(',').map(h => h.replace(/^"|"$/g, ''));
        const dataRows = rows.slice(1).map(row => {
            const cells = row.split(',').map(cell => cell.replace(/^"|"$/g, ''));
            return cells;
        });
        
        // Create Handsontable for editable CSV
        if (this.editableCsvTable) {
            this.editableCsvTable.destroy();
        }
        
        this.editableCsvTable = new Handsontable(editableTableContainer, {
            data: dataRows,
            columns: headers.map((header, index) => ({
                data: index,
                type: 'text'
            })),
            colHeaders: headers,
            rowHeaders: true,
            contextMenu: true,
            manualColumnResize: true,
            manualRowMove: true,
            licenseKey: 'non-commercial-and-evaluation',
            height: 300,
            afterChange: (changes, source) => {
                if (source === 'edit') {
                    this.updateCsvFromEditableTable();
                }
            }
        });
        
        // Show the editable table section
        const editableSection = document.getElementById('editableCsvSection');
        if (editableSection) {
            editableSection.classList.remove('d-none');
        }
        
        // Setup save and cancel buttons
        const saveBtn = document.getElementById('saveExpenses');
        const cancelBtn = document.getElementById('cancelEdit');
        
        if (saveBtn) {
            saveBtn.addEventListener('click', this.saveExpensesToDb.bind(this));
        }
        
        if (cancelBtn) {
            cancelBtn.addEventListener('click', this.cancelEdit.bind(this));
        }
    }
    
    async saveExpensesToDb() {
        if (!this.editableCsvTable) {
            Utils.showNotification('No data to save', 'warning');
            return;
        }
        
        const data = this.editableCsvTable.getData();
        const headers = this.editableCsvTable.getColHeader();
        
        try {
            // Define valid categories
            const validCategories = ['car', 'gas', 'grocery', 'home exp', 'home setup', 'gym', 'hospital', 'misc', 'rent', 'mortgage', 'restaurant', 'service', 'shopping', 'transport', 'utility', 'vacation'];
            
            // Convert table data to expense objects
            const expenses = [];
            const invalidCategories = [];
            
            data.forEach((row, index) => {
                if (row.length >= 4) {
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
                    
                    // Only add if we have valid data
                    if (expense.date && expense.description && expense.amount > 0) {
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
                Utils.showNotification('No valid expenses to save', 'warning');
                return;
            }
            
            // Save each expense to the database
            let savedCount = 0;
            for (const expense of expenses) {
                try {
                    console.log('Attempting to save expense:', expense);
                    const result = await ApiClient.expenses.create(this.dashboardId, expense);
                    console.log('Save result:', result);
                    savedCount++;
                } catch (error) {
                    console.error('Error saving expense:', error);
                    console.error('Error details:', error.message);
                }
            }
            
            console.log(`Total expenses saved: ${savedCount}`);
            Utils.showNotification(`Successfully saved ${savedCount} expenses to the database`, 'success');
            
            // Hide the editable section
            const editableSection = document.getElementById('editableCsvSection');
            if (editableSection) {
                editableSection.classList.add('d-none');
            }
            
        } catch (error) {
            console.error('Error saving expenses:', error);
            Utils.showNotification('Error saving expenses to database', 'danger');
        }
    }
    
    async saveCsvDataDirectly(csvData) {
        try {
            // Define valid categories
            const validCategories = ['car', 'gas', 'grocery', 'home exp', 'home setup', 'gym', 'hospital', 'misc', 'rent', 'mortgage', 'restaurant', 'service', 'shopping', 'transport', 'utility', 'vacation'];
            
            // Parse CSV data directly
            const rows = csvData.split('\n');
            const headers = rows[0].split(',').map(h => h.replace(/^"|"$/g, ''));
            const dataRows = rows.slice(1).map(row => {
                const cells = row.split(',').map(cell => cell.replace(/^"|"$/g, ''));
                return cells;
            });
            
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
            
            // Save each expense to the database
            let savedCount = 0;
            for (const expense of expenses) {
                try {
                    console.log('Attempting to save expense (direct):', expense);
                    const result = await ApiClient.expenses.create(this.dashboardId, expense);
                    console.log('Save result (direct):', result);
                    savedCount++;
                } catch (error) {
                    console.error('Error saving expense (direct):', error);
                    console.error('Error details (direct):', error.message);
                }
            }
            
            console.log(`Total expenses saved (direct): ${savedCount}`);
            Utils.showNotification(`Successfully saved ${savedCount} expenses to the database`, 'success');
            
            // Refresh all components after data ingress
            await this.refreshAllComponents();
            
        } catch (error) {
            console.error('Error saving CSV data:', error);
            Utils.showNotification('Error saving data to database', 'danger');
        }
    }

    async refreshAllComponents() {
        console.log('Refreshing all dashboard components after data ingress');
        
        try {
            // 1. Refresh month dropdown
            await this.setupMonthDropdown();
            
            // 2. Refresh monthly table with current selected month
            const selectedMonth = this.getSelectedMonthFromDropdown();
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
            console.error('Error refreshing components:', error);
            Utils.showNotification('Error refreshing dashboard components', 'danger');
        }
    }
    
    cancelEdit() {
        const editableSection = document.getElementById('editableCsvSection');
        if (editableSection) {
            editableSection.classList.add('d-none');
        }
        Utils.showNotification('Editing cancelled', 'info');
    }

    updateCsvFromEditableTable() {
        if (!this.editableCsvTable) return;
        
        const data = this.editableCsvTable.getData();
        const headers = this.editableCsvTable.getColHeader();
        
        // Convert back to CSV format
        const csvRows = [headers.join(',')];
        data.forEach(row => {
            const escapedRow = row.map(cell => `"${cell}"`);
            csvRows.push(escapedRow.join(','));
        });
        
        this.currentCsvData = csvRows.join('\n');
        
        // Update the preview as well
        this.showCsvPreview(this.currentCsvData);
        
        Utils.showNotification('CSV data updated. Your changes will be used in the next AI request.', 'info');
    }


    initMonthlyTable(selectedMonth = null) {
        console.log('=== initMonthlyTable() called with selectedMonth:', selectedMonth, '===');
        const container = document.getElementById('monthlyExpensesTable');
        if (!container) {
            console.error('Monthly table container not found!');
            return;
        }

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
                            console.log('Insert row above context menu triggered:', selection);
                            this.handleRowAddition(selection);
                        }
                    },
                    'row_below': {
                        name: 'Insert row below',
                        callback: (key, selection) => {
                            console.log('Insert row below context menu triggered:', selection);
                            this.handleRowAddition(selection);
                        }
                    },
                    'remove_row': {
                        name: 'Remove row',
                        callback: (key, selection) => {
                            console.log('Remove row context menu triggered:', selection);
                            this.handleRowRemoval(selection);
                        }
                    },
                    'sep1': '---------',
                    'alignment': {}
                }
            },
            manualColumnResize: true,
            manualRowMove: true,
            licenseKey: 'non-commercial-and-evaluation',
            height: 400, // Fixed height to prevent ResizeObserver issues
            afterChange: (changes, source) => {
                console.log('Handsontable afterChange called:', { 
                    changes: changes, 
                    source: source,
                    tableData: this.monthlyTable ? this.monthlyTable.getData() : 'No table'
                });
                
                // Only process user edits, ignore programmatic changes
                if (source === 'edit' && changes && changes.length > 0) {
                    console.log('Valid user edit detected, processing individual changes');
                    console.log('Changes details:', changes);
                    
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
                            
                            console.log('Calling updateMonthlyChanges for row ID:', rowId, 'with data:', expenseData);
                            this.updateMonthlyChanges(rowId, expenseData);
                        } else {
                            console.log('No row ID found for row:', row, 'skipping update');
                        }
                    });
                } else if (source !== 'loadData' && source !== 'autofill' && source !== 'empty') {
                    console.log('Ignoring non-edit change:', {
                        source: source,
                        changesCount: changes ? changes.length : 0,
                        changes: changes
                    });
                }
            },
            
            // Add additional event listeners for better change detection
            afterBeginEditing: (row, column) => {
                console.log('Cell editing started:', { row, column });
            },
            
            afterSelection: (row, column, row2, column2, preventScrolling) => {
                console.log('Cell selected:', { row, column });
            },
            
        });

        // If a month is selected, load data for that month
        if (selectedMonth) {
            console.log('Loading data for selected month:', selectedMonth);
            this.refreshMonthlyData(selectedMonth);
        } else {
            console.log('No month selected, table remains empty');
        }

    }

    async setupMonthDropdown() {
        console.log('=== setupMonthDropdown() called ===');
        const dropdownMenu = document.getElementById('monthDropdownMenu');
        const dropdownButton = document.getElementById('monthDropdown');
        
        if (!dropdownMenu || !dropdownButton) {
            console.error('Dropdown elements not found!');
            return null;
        }
        
        try {
            console.log('Setting up month dropdown from database...');
            const months = await this.getAvailableMonthsFromDb();
            console.log('Months from database:', months);
            
            let menuHtml = '';
            let selectedMonth = null;
            
            // If no months in database, keep dropdown blank
            if (months.length === 0) {
                console.log('No months found in database, keeping dropdown blank');
                menuHtml = '<li><a class="dropdown-item disabled" href="#">No data available</a></li>';
                dropdownButton.innerHTML = '<i class="fas fa-calendar me-1"></i>Select Month';
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
                console.log('Setting default month to:', selectedMonth, 'label:', defaultMonthLabel);
                dropdownButton.innerHTML = `<i class="fas fa-calendar me-1"></i>${defaultMonthLabel}`;
            }
            
            dropdownMenu.innerHTML = menuHtml;
            
            // Add event listeners to dropdown items
            const dropdownItems = dropdownMenu.querySelectorAll('.dropdown-item:not(.disabled)');
            dropdownItems.forEach(item => {
                item.addEventListener('click', (e) => {
                    e.preventDefault();
                    const selectedMonth = e.target.getAttribute('data-month');
                    console.log('Month selected from dropdown:', selectedMonth);
                    this.handleMonthChange(selectedMonth);
                    dropdownButton.innerHTML = `<i class="fas fa-calendar me-1"></i>${e.target.textContent}`;
                });
            });
            
            return selectedMonth;
            
        } catch (error) {
            console.error('Error setting up month dropdown:', error);
            // On error, keep dropdown blank
            dropdownMenu.innerHTML = '<li><a class="dropdown-item disabled" href="#">Error loading months</a></li>';
            dropdownButton.innerHTML = '<i class="fas fa-calendar me-1"></i>Select Month';
            return null;
        }
    }


    async setupUserDropdown() {
        console.log('=== setupUserDropdown() called ===');
        const dropdownMenu = document.getElementById('userDropdownMenu');
        const dropdownButton = document.getElementById('userDropdown');
        
        if (!dropdownMenu || !dropdownButton) {
            console.error('User dropdown elements not found!');
            return;
        }
        
        try {
            console.log('Setting up user dropdown from dashboard members...');
            const users = await this.getDashboardUsers();
            console.log('Dashboard users:', users);
            
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
                    console.log('User selected from dropdown:', selectedUserId, selectedUserName);
                    
                    this.handleUserChange(selectedUserId);
                    dropdownButton.innerHTML = `<i class="fas fa-user me-1"></i>${selectedUserName}`;
                });
            });
            
        } catch (error) {
            console.error('Error setting up user dropdown:', error);
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
            console.log('Dashboard members from API:', members);
            
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
            
            console.log('Unique users:', users);
            return users;
            
        } catch (error) {
            console.error('Error getting dashboard users:', error);
            // Fallback: return current user only
            return [{
                id: window.currentUserId || 1,
                name: window.currentUserName || 'Current User'
            }];
        }
    }

    getSelectedUserIdFromDropdown() {
        const dropdownButton = document.getElementById('userDropdown');
        if (!dropdownButton) return 'all';
        
        // Extract user ID from dropdown button text
        const buttonText = dropdownButton.textContent.trim();
        const activeItem = document.querySelector('#userDropdownMenu .dropdown-item.active');
        
        if (activeItem) {
            return activeItem.getAttribute('data-user-id') || 'all';
        }
        
        return 'all';
    }

    handleUserChange(selectedUserId) {
        console.log('Selected user:', selectedUserId);
        // Refresh the table with the selected user filter
        const selectedMonth = this.getSelectedMonthFromDropdown();
        this.refreshMonthlyData(selectedMonth, selectedUserId);
        Utils.showNotification(`Showing data for ${selectedUserId === 'all' ? 'all users' : 'selected user'}`, 'info');
    }

    async getAvailableMonthsFromDb() {
        try {
            console.log('Fetching expenses from API for dashboard:', this.dashboardId);
            const expenses = await ApiClient.expenses.get(this.dashboardId);
            console.log('Raw expenses from API:', expenses);
            
            // Extract unique months from expenses
            const availableMonths = new Set();
            expenses.forEach(expense => {
                console.log('Processing expense:', expense);
                if (expense.date) {
                    const month = expense.date.substring(0, 7); // YYYY-MM
                    console.log('Extracted month:', month, 'from date:', expense.date);
                    availableMonths.add(month);
                }
            });
            
            console.log('Available months set:', availableMonths);
            
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
                    console.log('Month object:', { value: month, label, year, monthNum, date: date.toString() });
                    return { value: month, label };
                });
            
            console.log('Final months array:', months);
            return months;
        } catch (error) {
            console.error('Error getting months from database:', error);
            return [];
        }
    }

    generateMonthOptions() {
        const months = [];
        const currentDate = new Date();
        
        for (let i = 0; i < 12; i++) {
            const date = new Date(currentDate.getFullYear(), currentDate.getMonth() - i, 1);
            const value = date.toISOString().substring(0, 7);
            const label = date.toLocaleDateString('en-US', { year: 'numeric', month: 'long' });
            months.push({ value, label });
        }
        
        return months;
    }

    handleMonthChange(selectedMonth) {
        console.log('Selected month:', selectedMonth);
        // Clear the current table and reload with data for the selected month
        if (this.monthlyTable) {
            // Clear the table first - use loadData with empty array
            this.monthlyTable.loadData([]);
            console.log('clearing monthly table - loadData([]) called');
        }
        
        // Load data for the selected month
        this.refreshMonthlyData(selectedMonth);
        Utils.showNotification(`Showing data for ${selectedMonth}`, 'info');
    }

    async handleRowRemoval(selection) {
        console.log('handleRowRemoval called with selection:', selection);
        
        try {
            const selectedMonth = this.getSelectedMonthFromDropdown();
            if (!selectedMonth) {
                Utils.showNotification('No month selected', 'warning');
                return;
            }
            
            // Get the row index that was removed
            const removedRowIndex = selection[0].start.row;
            console.log('Removing row at index:', removedRowIndex);
            
            // Get the expense ID directly from the Handsontable data
            if (this.monthlyTable) {
                const rowData = this.monthlyTable.getDataAtRow(removedRowIndex);
                console.log('Row data at index', removedRowIndex, ':', rowData);
                
                // The expense ID should be in the last column (use -1 indexing like Python)
                const expenseId = rowData[rowData.length - 1];
                console.log('Expense ID from table (last column):', expenseId);
                
                if (expenseId) {
                    console.log('Deleting expense with ID:', expenseId);
                    await ApiClient.expenses.delete(this.dashboardId, expenseId);
                    Utils.showNotification('Expense deleted successfully', 'success');
                    
                    // Remove the row from the table directly without full refresh
                    this.monthlyTable.alter('remove_row', removedRowIndex);
                    
                    // Update category breakdown from current table data
                    const currentTableData = this.monthlyTable.getData();
                    console.log('=== DEBUG: Current table data after row removal ===');
                    console.log('Number of rows:', currentTableData.length);
                    console.log('Expense IDs in table:', currentTableData.map(row => row[row.length - 1]));
                    console.log('Table data structure:', currentTableData);
                    this.updateCategoryBreakdownFromTableData(currentTableData);

                    // Refresh yearly table to reflect the changes
                    await this.initYearlyTable();
                } else {
                    console.error('No expense ID found in row data');
                    Utils.showNotification('Error: Could not find expense ID', 'danger');
                }
            }
        } catch (error) {
            console.error('Error handling row removal:', error);
            
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
            console.log('refreshMonthlyData called with month:', month, 'and user:', userId);
            const expenses = await ApiClient.expenses.get(this.dashboardId);
            console.log('Fetched expenses from API:', expenses);
            
            // Filter by month if specified
            let filteredExpenses = expenses;
            if (month) {
                console.log('Filtering for month:', month);
                filteredExpenses = expenses.filter(expense => {
                    const expenseMonth = expense.date.substring(0, 7); // YYYY-MM
                    return expenseMonth === month;
                });
            }
            
            // Filter by user if specified (not "all")
            if (userId && userId !== 'all') {
                console.log('Filtering for user:', userId);
                filteredExpenses = filteredExpenses.filter(expense => {
                    return expense.user_id == userId;
                });
            }
            
            console.log('Filtered expenses for month', month, 'and user', userId, ':', filteredExpenses);
            
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
                console.log('Loading table data into Handsontable:', tableData);
                this.monthlyTable.loadData(tableData);
            }

            // Update category breakdown
            this.updateCategoryBreakdown(filteredExpenses);
        } catch (error) {
            console.error('Error refreshing monthly data:', error);
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

        console.log('=== DEBUG: Processing table data for category breakdown ===');
        console.log('Table data type:', typeof tableData);
        console.log('Table data length:', tableData.length);
        console.log('First row sample:', tableData[0]);

        tableData.forEach((row, index) => {
            if (row && Array.isArray(row) && row.length >= 4) {
                // Handsontable data is in array format: [date, category, amount, description, user_name, id]
                const category = row[1]; // Column 1 is category
                const amount = parseFloat(row[2]) || 0; // Column 2 is amount
                
                console.log(`Row ${index}: category="${category}", amount=${amount}`);
                
                if (category && amount > 0) {
                    if (!categoryTotals[category]) {
                        categoryTotals[category] = 0;
                    }
                    categoryTotals[category] += amount;
                    totalAmount += amount;
                }
            }
        });

        console.log('Category totals:', categoryTotals);
        console.log('Total amount:', totalAmount);
        
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
            console.error('Error initializing yearly table:', error);
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
                    <div class="table-responsive">
                        <table class="table table-bordered table-sm">
                            <thead class="table-light">
                                <tr>
                                    <th>Category</th>
                                    ${monthHeaders.map(month => `<th>${month}</th>`).join('')}
                                    <th class="table-primary">Total</th>
                                </tr>
                            </thead>
                            <tbody>
            `;
            
            // Category rows
            categories.forEach(category => {
                const rowData = yearlyData[year][category];
                if (rowData) {
                    let categoryTotal = 0;
                    const monthCells = monthNames.map(month => {
                        const amount = rowData[month] || 0;
                        categoryTotal += amount;
                        return `<td class="text-end">${amount > 0 ? Utils.formatCurrency(amount) : '-'}</td>`;
                    }).join('');
                    
                    html += `
                        <tr>
                            <td class="fw-bold text-capitalize">${category}</td>
                            ${monthCells}
                            <td class="text-end fw-bold table-primary">${categoryTotal > 0 ? Utils.formatCurrency(categoryTotal) : '-'}</td>
                        </tr>
                    `;
                }
            });
            
            // Monthly totals row
            html += `
                        <tr class="table-secondary">
                            <td class="fw-bold">Monthly Total</td>
                            ${monthNames.map(month => {
                                const amount = monthlyTotals[month] || 0;
                                return `<td class="text-end fw-bold">${amount > 0 ? Utils.formatCurrency(amount) : '-'}</td>`;
                            }).join('')}
                            <td class="text-end fw-bold table-primary">${yearlyTotal > 0 ? Utils.formatCurrency(yearlyTotal) : '-'}</td>
                        </tr>
            `;
            
            html += `
                            </tbody>
                        </table>
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
                console.error('No row ID provided for update');
                return;
            }
            
            if (!rowData || !rowData.date || !rowData.description || !rowData.amount) {
                console.error('Invalid row data for update:', rowData);
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
                console.log('New expense created:', result);
                
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
            console.error('Error updating monthly changes:', error);
            
            // Handle 403 Forbidden errors specifically
            if (error.status === 403) {
                Utils.showNotification(error.message || 'You do not have permission to edit this expense', 'danger');
            } else {
                Utils.showNotification('Error saving expense: ' + error.message, 'danger');
            }
        }
    }
    
    async handleRowAddition(selection) {
        console.log('handleRowAddition called with selection:', selection);
        
        try {
            const selectedMonth = this.getSelectedMonthFromDropdown();
            if (!selectedMonth) {
                Utils.showNotification('No month selected', 'warning');
                return;
            }
            
            // Get the row index where the new row should be added
            const rowIndex = selection[0].start.row;
            console.log('Adding new row at index:', rowIndex);
            
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
            console.error('Error handling row addition:', error);
            Utils.showNotification('Error adding new row', 'danger');
        }
    }
    
    addSaveButtonToRow(rowIndex) {
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
            console.log('Saving new row data:', rowData);
            
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
            console.log('New expense created:', result);
            
            // Remove the save button
            this.removeSaveButtonFromRow(rowIndex);
            
            // Refresh the table to get the new expense with its real ID
            const selectedMonth = this.getSelectedMonthFromDropdown();
            if (selectedMonth) {
                await this.refreshMonthlyData(selectedMonth);
            }
            
            Utils.showNotification('New expense saved successfully', 'success');
            
        } catch (error) {
            console.error('Error saving new row:', error);
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
    
    async saveMonthlyChanges() {
        // This function is now deprecated - individual operations are handled separately
        console.log('saveMonthlyChanges is deprecated - use individual update/delete/add functions');
        Utils.showNotification('Individual row operations are now handled separately', 'info');
    }


    async refreshYearlyData() {
        try {
            // In production, this would fetch aggregated yearly data
            console.log('Refreshing yearly data');
        } catch (error) {
            console.error('Error refreshing yearly data:', error);
        }
    }

    addManualSaveButton() {
        // Create a manual save button for testing
        const container = document.getElementById('monthlyExpensesTable');
        if (!container) return;
        
        const saveButton = document.createElement('button');
        saveButton.className = 'btn btn-primary mt-3';
        saveButton.innerHTML = '<i class="fas fa-save me-1"></i>Save Changes Manually';
        saveButton.addEventListener('click', () => {
            console.log('Manual save button clicked');
            this.saveMonthlyChanges();
        });
        
        container.parentNode.insertBefore(saveButton, container.nextSibling);
    }

    resetUploadUI() {
        const optionCards = document.querySelectorAll('.option-card');
        const sheetsPasteArea = document.getElementById('sheetsPasteArea');
        const aiUploadArea = document.getElementById('aiUploadArea');
        const processingArea = document.getElementById('processingArea');
        const csvPreviewArea = document.getElementById('csvPreviewArea');
        const aiChatCard = document.getElementById('aiChatCard');
        
        // Reset all UI elements
        optionCards.forEach(card => {
            card.classList.remove('d-none');
        });
        if (sheetsPasteArea) sheetsPasteArea.classList.add('d-none');
        if (aiUploadArea) aiUploadArea.classList.add('d-none');
        if (processingArea) processingArea.classList.add('d-none');
        if (csvPreviewArea) csvPreviewArea.classList.add('d-none');
        if (aiChatCard) aiChatCard.classList.add('d-none');
        
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
    }
}

// Invitation functionality
function initializeInvitationFunctionality() {
    const inviteUserBtn = document.getElementById('inviteUser');
    if (inviteUserBtn) {
        inviteUserBtn.addEventListener('click', sendInvitation);
    }
}

async function sendInvitation() {
    const emailInput = document.getElementById('shareEmail');
    const messageInput = document.getElementById('invitationMessage');
    const email = emailInput.value.trim();
    const message = messageInput.value.trim();
    
    if (!email) {
        Utils.showNotification('Please enter an email address', 'warning');
        return;
    }
    
    if (!validateEmail(email)) {
        Utils.showNotification('Please enter a valid email address', 'warning');
        return;
    }
    
    try {
        const dashboardId = window.location.pathname.split('/').pop();
        const response = await fetch(`/api/dashboard/${dashboardId}/invite`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                email: email,
                message: message
            })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            Utils.showNotification('Invitation sent successfully!', 'success');
            
            // Clear form and close modal
            emailInput.value = '';
            messageInput.value = '';
            const modal = bootstrap.Modal.getInstance(document.getElementById('shareDashboardModal'));
            modal.hide();
        } else {
            Utils.showNotification(result.error || 'Failed to send invitation', 'danger');
        }
    } catch (error) {
        console.error('Error sending invitation:', error);
        Utils.showNotification('Network error: ' + error.message, 'danger');
    }
}

function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
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
        console.error('Error loading edit mode settings:', error);
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
        console.error('Error saving edit mode:', error);
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
