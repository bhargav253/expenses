#!/usr/bin/env python3
"""
Unit test for AI processing with DeepSeek API
This script allows you to test AI processing with your own API key, file (PDF or CSV), and prompt.
"""

import os
import sys
import base64
import requests
import argparse
from pathlib import Path

try:
    import camelot
    PDF_EXTRACTION_AVAILABLE = True
except ImportError:
    PDF_EXTRACTION_AVAILABLE = False
    print("⚠️  camelot-py not available. Install with: pip install camelot-py")

def test_ai_processing(api_key, file_path, prompt=""):
    """
    Test AI processing with DeepSeek API for PDF or CSV files
    
    Args:
        api_key (str): Your DeepSeek API key
        file_path (str): Path to the PDF or CSV file to test
        prompt (str): Optional prompt for the AI
    """
    
    file_extension = Path(file_path).suffix.lower()
    filename = Path(file_path).name
    
    print(f"🧪 Testing AI processing for: {filename}")
    print(f"📝 Prompt: {prompt}")
    print(f"📄 File type: {file_extension}")
    print("-" * 50)
    
    if file_extension == '.pdf':
        return test_pdf_processing(api_key, file_path, prompt)
    elif file_extension == '.csv':
        return test_csv_processing(api_key, file_path, prompt)
    else:
        print(f"❌ Unsupported file type: {file_extension}. Please use .pdf or .csv files.")
        return

def test_pdf_processing(api_key, pdf_path, prompt=""):
    """
    Test PDF processing with DeepSeek API
    """
    filename = Path(pdf_path).name
    
    # Extract text from PDF using Camelot
    print("📄 Extracting text from PDF using Camelot...")
    extracted_text = extract_text_from_pdf(pdf_path)
    
    if not extracted_text:
        print("❌ Failed to extract text from PDF")
        return
    
    print(f"✅ Text extraction successful")
    print(f"   Extracted text size: {len(extracted_text):,} characters")
    print(f"   Estimated tokens: {len(extracted_text) // 4:,}")
    
    # Check if chunking is needed
    if len(extracted_text) > 50000:  # Conservative limit for text
        print(f"⚠️  TEXT TOO LARGE: Extracted text ({len(extracted_text):,} chars) may exceed token limits")
        print(f"   Would be split into {len(extracted_text) // 20000 + 1} chunks")
    else:
        print("✅ Text size is within reasonable limits")
    
    # Call DeepSeek API with extracted text
    url = "https://api.deepseek.com/v1/chat/completions"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    # Create system prompt for text processing
    system_prompt = """You are a financial document processing assistant. You extract transaction data from bank statements and convert it to CSV format.
    
    Extract all transactions from the bank statement text and return them in CSV format with these columns:
    - Date (format: YYYY-MM-DD)
    - Description (the merchant or transaction description)
    - Amount (numeric value, positive for expenses)
    - Category (use one of: car, gas, grocery, home exp, home setup, gym, hospital, misc, rent, mortgage, restaurant, service, shopping, transport, utility, vacation)
    
    Only include actual transactions, not headers or totals. If you can't determine the category, use 'misc'.
    Return only the CSV data, no additional text.
    """
    
    # Build user message with extracted text
    if prompt:
        user_message = f"Extract transaction data from this bank statement ({filename}). Here's the extracted text:\n\n{extracted_text}\n\nAdditional instructions: {prompt}"
    else:
        user_message = f"Extract transaction data from this bank statement ({filename}). Here's the extracted text:\n\n{extracted_text}"
    
    payload = {
        "model": "deepseek-chat",
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_message
            }
        ],
        "temperature": 0.1,
        "max_tokens": 2000
    }
    
    print(f"\n📤 Sending request to DeepSeek API with extracted text...")
    print(f"   Total message size: {len(user_message):,} characters")
    
    return call_deepseek_api_and_process_response(api_key, payload, filename)

def test_csv_processing(api_key, csv_path, prompt=""):
    """
    Test CSV processing with DeepSeek API
    """
    filename = Path(csv_path).name
    
    # Read CSV file
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            csv_content = f.read()
        
        print(f"📊 CSV file loaded: {len(csv_content):,} characters")
        print(f"   Estimated tokens: {len(csv_content) // 4:,}")
        
        # Check if chunking is needed
        if len(csv_content) > 50000:  # Conservative limit for text
            print(f"⚠️  CSV TOO LARGE: CSV content ({len(csv_content):,} chars) may exceed token limits")
            print(f"   Would be split into {len(csv_content) // 20000 + 1} chunks")
        else:
            print("✅ CSV size is within reasonable limits")
        
    except Exception as e:
        print(f"❌ Error reading CSV file: {e}")
        return
    
    # Call DeepSeek API with CSV content
    url = "https://api.deepseek.com/v1/chat/completions"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    # Create system prompt for CSV processing
    system_prompt = """You are a CSV data processing assistant. You help users filter, categorize, and transform their expense data.
    
    The user will provide CSV data and a request. You should:
    1. Understand the user's request
    2. Process the CSV data accordingly
    3. Return the processed CSV data
    4. Provide a brief explanation of what you did
    
    Always return valid CSV format. Keep the same column structure unless explicitly requested to change it.
    For categorization, use these categories: car, gas, grocery, home exp, home setup, gym, hospital, misc, rent, mortgage, restaurant, service, shopping, transport, utility, vacation.
    
    Example responses:
    - "I've filtered the data to show only transactions above $50. Here's the processed CSV:"
    - "I've categorized the expenses based on the descriptions. Here's the updated CSV:"
    """
    
    # Build user message with CSV content
    if prompt:
        user_message = f"Process this CSV data according to the following instructions:\n\n{prompt}\n\nCSV Data:\n{csv_content}"
    else:
        user_message = f"Please analyze and process this CSV data:\n\n{csv_content}"
    
    payload = {
        "model": "deepseek-chat",
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_message
            }
        ],
        "temperature": 0.1,
        "max_tokens": 2000
    }
    
    print(f"\n📤 Sending request to DeepSeek API with CSV data...")
    print(f"   Total message size: {len(user_message):,} characters")
    
    return call_deepseek_api_and_process_response(api_key, payload, filename)

def test_chunking_logic(pdf_path):
    """
    Test the chunking logic without making API calls
    """
    print(f"\n🧪 Testing chunking logic for: {pdf_path}")
    print("-" * 50)
    
    try:
        with open(pdf_path, 'rb') as f:
            pdf_bytes = f.read()
        
        pdf_base64 = base64.b64encode(pdf_bytes).decode('utf-8')
        
        print(f"PDF file size: {len(pdf_bytes):,} bytes")
        print(f"Base64 data size: {len(pdf_base64):,} characters")
        
        # Test chunking
        chunk_size = 40000
        chunks = [pdf_base64[i:i+chunk_size] for i in range(0, len(pdf_base64), chunk_size)]
        
        print(f"Number of chunks: {len(chunks)}")
        print(f"Chunk sizes: {[len(chunk) for chunk in chunks]}")
        
        # Estimate tokens per chunk
        for i, chunk in enumerate(chunks):
            estimated_tokens = len(chunk) // 4
            print(f"Chunk {i+1}: {len(chunk):,} chars → ~{estimated_tokens:,} tokens")
            
    except Exception as e:
        print(f"❌ Error testing chunking: {e}")

def test_pdf_extraction_with_chunking(api_key, pdf_path, prompt=""):
    """
    Test PDF extraction with full chunking implementation (multiple API calls)
    """
    print(f"\n🧪 Testing PDF extraction WITH CHUNKING for: {pdf_path}")
    print(f"Prompt: {prompt}")
    print("=" * 60)
    
    # Read and encode PDF file
    try:
        with open(pdf_path, 'rb') as f:
            pdf_bytes = f.read()
        
        pdf_base64 = base64.b64encode(pdf_bytes).decode('utf-8')
        
        print(f"📄 PDF Analysis:")
        print(f"   File size: {len(pdf_bytes):,} bytes")
        print(f"   Base64 size: {len(pdf_base64):,} characters")
        
        # Estimate token count
        estimated_tokens = len(pdf_base64) // 4
        print(f"   Estimated tokens: {estimated_tokens:,}")
        
        # Check if chunking is needed
        if estimated_tokens > 131072:
            print(f"⚠️  CHUNKING REQUIRED: Estimated tokens ({estimated_tokens:,}) exceeds 131,072 limit")
        else:
            print("✅ Single API call sufficient")
        
    except Exception as e:
        print(f"❌ Error reading PDF file: {e}")
        return
    
    # Split into chunks (same logic as production)
    chunk_size = 40000
    chunks = [pdf_base64[i:i+chunk_size] for i in range(0, len(pdf_base64), chunk_size)]
    
    print(f"\n📦 Chunking Information:")
    print(f"   Number of chunks: {len(chunks)}")
    print(f"   Chunk sizes: {[len(chunk) for chunk in chunks]}")
    
    # Process each chunk with API calls
    all_transactions = []
    total_api_calls = 0
    successful_calls = 0
    
    print(f"\n🚀 Processing {len(chunks)} chunks with API calls...")
    
    for i, chunk in enumerate(chunks):
        print(f"\n📤 Processing chunk {i+1}/{len(chunks)}...")
        
        # Build user message for this chunk
        filename = Path(pdf_path).name
        if prompt:
            user_message = f"Extract transaction data from this part of the PDF file ({filename}, chunk {i+1}/{len(chunks)}). Here's the PDF content: {chunk}\n\nAdditional instructions: {prompt}"
        else:
            user_message = f"Extract transaction data from this part of the PDF file ({filename}, chunk {i+1}/{len(chunks)}). Here's the PDF content: {chunk}"
        
        # Call DeepSeek API for this chunk
        result = call_deepseek_api_for_chunk(api_key, user_message)
        total_api_calls += 1
        
        if result:
            successful_calls += 1
            chunk_transactions = extract_csv_from_response(result)
            all_transactions.extend(chunk_transactions)
            print(f"✅ Chunk {i+1} processed successfully: {len(chunk_transactions)} transactions")
        else:
            print(f"❌ Chunk {i+1} failed")
        
        # Small delay between API calls
        import time
        time.sleep(1)
    
    print(f"\n📊 Chunk Processing Summary:")
    print(f"   Total API calls: {total_api_calls}")
    print(f"   Successful calls: {successful_calls}")
    print(f"   Failed calls: {total_api_calls - successful_calls}")
    
    # Combine and deduplicate results
    if all_transactions:
        combined_csv = combine_and_deduplicate_transactions(all_transactions)
        print(f"\n🎯 Final Results:")
        line_count = len(combined_csv.split('\n')) - 1  # Subtract header
        print(f"   Total unique transactions: {line_count}")
        print(f"   Combined CSV size: {len(combined_csv)} characters")
        
        print(f"\n📋 Final CSV Data:")
        print("-" * 50)
        print(combined_csv)
        print("-" * 50)
        
        # Save to file for inspection
        output_file = f"chunked_result_{Path(pdf_path).stem}.csv"
        with open(output_file, 'w') as f:
            f.write(combined_csv)
        print(f"\n💾 Results saved to: {output_file}")
        
    else:
        print(f"\n❌ No transactions extracted from any chunks")

def call_deepseek_api_for_chunk(api_key, user_message):
    """
    Call DeepSeek API for a single chunk
    """
    url = "https://api.deepseek.com/v1/chat/completions"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    # Create system prompt for PDF extraction
    system_prompt = """You are a PDF document processing assistant. You extract financial transaction data from bank statements and convert it to CSV format.
    
    Extract all transactions from the PDF document and return them in CSV format with these columns:
    - Date (format: YYYY-MM-DD)
    - Description (the merchant or transaction description)
    - Amount (numeric value, positive for expenses)
    - Category (use one of: car, gas, grocery, home exp, home setup, gym, hospital, misc, rent, mortgage, restaurant, service, shopping, transport, utility, vacation)
    
    Only include actual transactions, not headers or totals. If you can't determine the category, use 'misc'.
    Return only the CSV data, no additional text.
    """
    
    payload = {
        "model": "deepseek-chat",
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_message
            }
        ],
        "temperature": 0.1,
        "max_tokens": 2000
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=60)
        
        if response.status_code != 200:
            print(f"   API Error: {response.status_code} - {response.text[:200]}...")
            return None
        
        result = response.json()
        ai_response = result['choices'][0]['message']['content']
        
        # Extract usage information
        usage = result.get('usage', {})
        print(f"   API Usage: {usage.get('prompt_tokens', 'N/A')} prompt, {usage.get('completion_tokens', 'N/A')} completion, {usage.get('total_tokens', 'N/A')} total")
        
        return ai_response
        
    except Exception as e:
        print(f"   API Call failed: {e}")
        return None

def extract_csv_from_response(ai_response):
    """
    Extract CSV data from AI response
    """
    lines = ai_response.split('\n')
    csv_lines = []
    
    for line in lines:
        if ',' in line and (line.startswith('"') or any(char.isdigit() for char in line)):
            csv_lines.append(line.strip())
        elif line.strip().lower().startswith('date,description,amount,category'):
            csv_lines.append(line.strip())
    
    return csv_lines

def combine_and_deduplicate_transactions(all_transactions):
    """
    Combine transactions from all chunks and remove duplicates
    """
    if not all_transactions:
        return "Date,Description,Amount,Category\n# No transactions extracted"
    
    # Remove header lines except the first one
    headers_removed = []
    header_found = False
    
    for line in all_transactions:
        if line.lower().startswith('date,description,amount,category'):
            if not header_found:
                headers_removed.append(line)
                header_found = True
        else:
            headers_removed.append(line)
    
    # Remove exact duplicates
    unique_transactions = []
    seen = set()
    
    for line in headers_removed:
        if line not in seen:
            unique_transactions.append(line)
            seen.add(line)
    
    return '\n'.join(unique_transactions)

def extract_text_from_pdf(pdf_path):
    """
    Extract text from PDF file using Camelot (preserves table structure)
    """
    if not PDF_EXTRACTION_AVAILABLE:
        print("❌ camelot-py not available. Install with: pip install camelot-py")
        return None
    
    try:
        print(f"Extracting tables from PDF using Camelot: {pdf_path}")
        
        text_content = ""
        
        # Try stream method first (better for bank statements without clear borders)
        try:
            print("Trying stream method...")
            tables = camelot.read_pdf(pdf_path, flavor='stream', pages='all')
            if tables:
                print(f"Stream method found {len(tables)} tables")
                for table_num, table in enumerate(tables):
                    if table is not None and not table.df.empty:
                        print(f"Table {table_num + 1} shape: {table.df.shape}")
                        print(f"Table {table_num + 1} accuracy: {table.accuracy}")
                        print(f"Table {table_num + 1} whitespace: {table.whitespace}")
                        
                        text_content += f"--- Table {table_num + 1} (Stream) ---\n"
                        table_text = table.df.to_string(index=False)
                        text_content += table_text + "\n\n"
                        
                        # Print first few rows for debugging
                        print(f"First 3 rows of table {table_num + 1}:")
                        print(table.df.head(3).to_string(index=False))
                        print()
            else:
                print("No tables found with stream method")
        except Exception as e:
            print(f"Stream method failed: {e}")
        
        # If no tables found with stream, try lattice method
        if not text_content:
            try:
                print("Trying lattice method...")
                tables = camelot.read_pdf(pdf_path, flavor='lattice', pages='all')
                if tables:
                    print(f"Lattice method found {len(tables)} tables")
                    for table_num, table in enumerate(tables):
                        if table is not None and not table.df.empty:
                            print(f"Table {table_num + 1} shape: {table.df.shape}")
                            print(f"Table {table_num + 1} accuracy: {table.accuracy}")
                            
                            text_content += f"--- Table {table_num + 1} (Lattice) ---\n"
                            table_text = table.df.to_string(index=False)
                            text_content += table_text + "\n\n"
                            
                            # Print first few rows for debugging
                            print(f"First 3 rows of table {table_num + 1}:")
                            print(table.df.head(3).to_string(index=False))
                            print()
                else:
                    print("No tables found with lattice method")
            except Exception as e:
                print(f"Lattice method failed: {e}")
        
        # If still no tables found, try PyPDF2 as fallback for text extraction
        if not text_content:
            print("No tables found with Camelot, trying PyPDF2 text extraction...")
            try:
                from PyPDF2 import PdfReader
                pdf_reader = PdfReader(pdf_path)
                for page_num, page in enumerate(pdf_reader.pages):
                    page_text = page.extract_text()
                    if page_text.strip():
                        text_content += f"--- Page {page_num + 1} Text ---\n"
                        text_content += page_text + "\n\n"
                        print(f"Page {page_num + 1} text extracted ({len(page_text)} chars)")
            except Exception as e:
                print(f"PyPDF2 text extraction failed: {e}")
        
        print(f"Total extracted content: {len(text_content)} characters")
        return text_content.strip()
            
    except Exception as e:
        print(f"❌ Error extracting text from PDF with Camelot: {e}")
        import traceback
        traceback.print_exc()
        return None

def call_deepseek_api_and_process_response(api_key, payload, filename):
    """
    Call DeepSeek API and process the response
    """
    url = "https://api.deepseek.com/v1/chat/completions"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        print(f"url : {url} \n headers : {headers} \n payload : {payload}")
        response = requests.post(url, headers=headers, json=payload, timeout=60)
        print(f"📥 API Response Status: {response.status_code}")
        
        if response.status_code != 200:
            print(f"❌ API Error: {response.text}")
            return
        
        result = response.json()
        ai_response = result['choices'][0]['message']['content']
        
        # Extract usage information
        usage = result.get('usage', {})
        print(f"📊 API Usage:")
        print(f"   Prompt tokens: {usage.get('prompt_tokens', 'N/A')}")
        print(f"   Completion tokens: {usage.get('completion_tokens', 'N/A')}")
        print(f"   Total tokens: {usage.get('total_tokens', 'N/A')}")
        
        print(f"\n🤖 AI Response ({len(ai_response)} characters):")
        print("-" * 50)
        print(ai_response)
        print("-" * 50)
        
        # Extract and display CSV data
        lines = ai_response.split('\n')
        csv_lines = []
        
        for line in lines:
            if ',' in line and (line.startswith('"') or any(char.isdigit() for char in line)):
                csv_lines.append(line.strip())
            elif line.strip().lower().startswith('date,description,amount,category'):
                csv_lines.append(line.strip())
        
        if csv_lines:
            print(f"\n📊 Extracted CSV Data ({len(csv_lines)} lines):")
            for line in csv_lines:
                print(f"   {line}")
            
            # Save to file for inspection
            output_file = f"ai_processed_{Path(filename).stem}.csv"
            with open(output_file, 'w') as f:
                f.write('\n'.join(csv_lines))
            print(f"\n💾 Results saved to: {output_file}")
        else:
            print("\n❌ No CSV data found in AI response")
            
    except requests.exceptions.Timeout:
        print("❌ API request timed out")
    except requests.exceptions.RequestException as e:
        print(f"❌ API request failed: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def main():
    parser = argparse.ArgumentParser(description='Test AI processing with DeepSeek API')
    parser.add_argument('--api-key', required=True, help='DeepSeek API key')
    parser.add_argument('--file', required=True, help='Path to PDF or CSV file')
    parser.add_argument('--prompt', default='', help='Optional prompt for the AI')
    parser.add_argument('--test-chunking', action='store_true', help='Test chunking logic only (no API calls)')
    parser.add_argument('--with-chunking', action='store_true', help='Test with full chunking implementation (multiple API calls)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"❌ File not found: {args.file}")
        return
    
    file_extension = Path(args.file).suffix.lower()
    
    if file_extension == '.pdf':
        if args.test_chunking:
            test_chunking_logic(args.file)
        elif args.with_chunking:
            test_pdf_extraction_with_chunking(args.api_key, args.file, args.prompt)
        else:
            test_ai_processing(args.api_key, args.file, args.prompt)
    elif file_extension == '.csv':
        test_ai_processing(args.api_key, args.file, args.prompt)
    else:
        print(f"❌ Unsupported file type: {file_extension}. Please use .pdf or .csv files.")

if __name__ == "__main__":
    main()
