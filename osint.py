# Advanced OSINT Toolkit (AI-Powered) - Developed by Enish Shah]
# Copyright (c) 2025 [Enish Shah]
# This toolkit is an open-source project for ethical hacking and threat intelligence.
# It integrates WHOIS, subdomains, emails, vulnerabilities, entities, and sentiment analysis.
# Features fallbacks for missing dependencies to ensure reliability.
# Usage: Run with python3 osint.py; install dependencies via pip install -r requirements.txt.
# For viva presentation: Demonstrates AI-driven OSINT with user-friendly GUI.

import tkinter as tk  # For creating the graphical user interface
from tkinter import ttk, scrolledtext, messagebox, filedialog  # Additional Tkinter components for UI elements
import subprocess  # For running external commands like nmap
import threading  # For running scans in background threads to keep UI responsive
import os  # For file operations like saving reports or deleting temp files
import re  # For regular expressions used in pattern matching (e.g., emails, dates)
import socket  # For network operations like subdomain checks and port scans
import concurrent.futures  # For parallel execution of subdomain checks to speed up scanning
from datetime import datetime  # For timestamps in reports and domain age calculations
import platform  # To detect the operating system (e.g., Windows vs. Linux)
import requests  # For making HTTP requests to APIs and websites
import urllib3  # For handling HTTP connections and disabling warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # Disable SSL warnings for non-critical fetches

try:
    import whois  # For WHOIS lookups; fallback if not installed
except ImportError:
    whois = None  # Set to None if module is missing

try:
    import dns.resolver  # For DNS queries; not used in this version but imported for potential future use
except ImportError:
    dns = None  # Set to None if module is missing

try:
    import spacy  # For natural language processing in entity extraction
    from bs4 import BeautifulSoup  # For parsing HTML from websites
    nlp = spacy.load('en_core_web_sm')  # Load English NLP model
    SPACY_AVAILABLE = True  # Flag to indicate if spaCy is ready
except Exception:
    nlp = None  # Fallback if loading fails
    SPACY_AVAILABLE = False  # Disable features requiring spaCy

try:
    from dateutil.parser import parse as date_parse  # For parsing dates from WHOIS data
except ImportError:
    date_parse = None  # Fallback if module is missing

# Sentiment Analysis section - Attempts to import libraries for AI sentiment processing
try:
    from transformers import pipeline  # For Hugging Face sentiment analysis pipeline
    import matplotlib.pyplot as plt  # For creating sentiment graphs
    from PIL import Image, ImageTk  # For displaying images in Tkinter GUI
    SENTIMENT_AVAILABLE = True  # Flag to enable sentiment features
except ImportError:
    SENTIMENT_AVAILABLE = False  # Disable if any library is missing

IS_WINDOWS = platform.system() == "Windows"  # Detect OS for path adjustments (e.g., nmap)

# --- AI WHOIS Analysis Function ---
# This function analyzes raw WHOIS text to extract key info and identify risks using regex patterns.
# Fallback method when advanced NLP is unavailable.
def ai_whois_analysis_fallback(raw_text):
    creation_date = None  # Variable to store creation date
    expiration_date = None  # Variable to store expiration date
    registrar = None  # Variable to store registrar name
    emails = []  # List to store found emails
    privacy_protection = False  # Flag for privacy protection detection

    # Regex patterns for extracting specific fields from WHOIS text
    creation_pattern = re.compile(r'Creation Date:\s*(.*)', re.IGNORECASE)
    expiration_pattern = re.compile(r'Expiration Date:\s*(.*)', re.IGNORECASE)
    registrar_pattern = re.compile(r'Registrar:\s*(.*)', re.IGNORECASE)
    email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    privacy_pattern = re.compile(r'privacy protection', re.IGNORECASE)

    # Search for matches in the raw text
    creation_match = creation_pattern.search(raw_text)
    if creation_match:
        creation_date = creation_match.group(1).strip()  # Extract and clean creation date
    expiration_match = expiration_pattern.search(raw_text)
    if expiration_match:
        expiration_date = expiration_match.group(1).strip()  # Extract and clean expiration date
    registrar_match = registrar_pattern.search(raw_text)
    if registrar_match:
        registrar = registrar_match.group(1).strip()  # Extract and clean registrar
    emails = email_pattern.findall(raw_text)  # Find all emails
    privacy_protection = bool(privacy_pattern.search(raw_text))  # Check for privacy flag

    risks = []  # List for potential risks
    recommendations = []  # List for recommendations
    summary = []  # List for summary output

    # Build summary strings
    summary.append(f"Registrar: {registrar if registrar else 'Unknown'}")
    summary.append(f"Creation Date: {creation_date if creation_date else 'Unknown'}")
    summary.append(f"Expiration Date: {expiration_date if expiration_date else 'Unknown'}")
    summary.append(f"Emails found: {len(emails)}")
    summary.append(f"Privacy Protection: {'Yes' if privacy_protection else 'No'}")

    # Calculate domain age if possible
    if creation_date and date_parse:
        try:
            cdate = date_parse(creation_date)  # Parse the date
            age_days = (datetime.now() - cdate).days  # Calculate age in days
            summary.append(f"Domain age: {age_days} days")
            if age_days < 365:
                risks.append(f"Domain is very new ({age_days} days old), which can be suspicious.")  # Add risk if new
        except:
            pass  # Skip if parsing fails

    # Add privacy risk if detected
    if privacy_protection:
        risks.append("Domain uses privacy protection, which can hide registrant details.")

    # Check for generic emails in risks
    if emails:
        generic_emails = [e for e in emails if re.search(r'(admin|support|contact|info|webmaster|sales|security)@', e, re.IGNORECASE)]
        if generic_emails:
            risks.append(f"Generic emails found: {', '.join(generic_emails)}")

    # Build recommendations based on risks
    if risks:
        recommendations.append("Review the following potential risks:")
        recommendations.extend(risks)
    else:
        recommendations.append("No obvious risks detected in WHOIS data.")

    # Return structured results
    return {'summary': '\n'.join(summary), 'risks': risks, 'recommendations': '\n'.join(recommendations)}

# --- AI Email Module Class ---
# This class handles name extraction and email pattern generation using NLP or regex fallback.
class AIEmailModule:
    def __init__(self):
        self.spacy_available = SPACY_AVAILABLE  # Check if spaCy is available
        self.nlp = nlp  # Load NLP model if available

    def extract_names(self, text):
        if self.spacy_available and self.nlp and text:
            doc = self.nlp(text)  # Process text with spaCy
            names = set()
            for ent in doc.ents:
                if ent.label_ == 'PERSON':
                    names.add(ent.text)  # Collect unique person names
            return list(names)
        else:
            if not text:
                return []  # Return empty if no text
            pattern = re.compile(r"\b([A-Z][a-z]+(?:\s[A-Z][a-z]+)?)\b")  # Regex for name patterns
            matches = pattern.findall(text)
            return list(set(matches))  # Return unique names

    def generate_patterns(self, names, domain):
        patterns = set()  # Use set to avoid duplicates
        for name in names:
            parts = name.lower().split()  # Split name into parts
            if len(parts) == 2:
                first, last = parts
                # Add common email patterns
                patterns.update({
                    f"{first}.{last}@{domain}",
                    f"{first}{last}@{domain}",
                    f"{first[0]}{last}@{domain}",
                    f"{first}@{domain}",
                    f"{last}@{domain}",
                    f"{last}.{first}@{domain}",
                    f"{last}{first}@{domain}",
                    f"{first[0]}.{last}@{domain}",
                    f"{last[0]}.{first}@{domain}",
                    f"{first[0]}{last[0]}@{domain}"
                })
            elif len(parts) == 1:
                first = parts[0]
                patterns.add(f"{first}@{domain}")  # Simple pattern for single name
        return list(patterns)  # Return as list

    def validate_emails(self, emails):
        email_regex = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")  # Regex for valid emails
        return [email for email in emails if email_regex.match(email)]  # Filter valid ones

# --- Entity Extractor Class ---
# This class extracts entities from text or URLs using spaCy, with fallbacks for errors.
class EntityExtractor:
    def __init__(self):
        if not SPACY_AVAILABLE or nlp is None:
            raise ImportError("spaCy or BeautifulSoup is not installed.")  # Error if dependencies missing
        self.nlp = nlp  # Load NLP model

    def extract_from_text(self, text):
        doc = self.nlp(text)  # Process text
        entities = {}  # Dictionary for entity types
        for ent in doc.ents:
            if ent.label_ not in entities:
                entities[ent.label_] = []  # Initialize list for type
            if ent.text not in entities[ent.label_]:
                entities[ent.label_].append(ent.text)  # Add unique entity
        return entities  # Return entities

    def extract_from_url(self, url, timeout=12):
        fallback_paths = ['', '/about', '/robots.txt']  # Paths to try if main URL fails
        last_error = ''  # Track last error
        for scheme in ['https', 'http']:  # Try HTTPS then HTTP
            for path in fallback_paths:
                try:
                    full_url = url if url.startswith('http') else f"{scheme}://{url}{path}"  # Build full URL
                    resp = requests.get(full_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=timeout, verify=False)  # Fetch page
                    if resp.status_code == 200 and len(resp.text) > 100:
                        soup = BeautifulSoup(resp.text, "html.parser")  # Parse HTML
                        text = soup.get_text(separator=' ', strip=True)  # Extract clean text
                        return self.extract_from_text(text)  # Extract entities
                except requests.exceptions.RequestException as e:
                    last_error = str(e)  # Update error
                    continue  # Try next path/scheme
        return {"Error": f"Could not fetch homepage or fallback for entity extraction. Last error: {last_error}"}  # Return error if all fail

# --- Sentiment Analyzer Class ---
# This class handles sentiment analysis using Hugging Face and graphs results with matplotlib.
class SentimentAnalyzer:
    def __init__(self):
        self.available = SENTIMENT_AVAILABLE  # Check availability
        if self.available:
            try:
                self.pipeline = pipeline("sentiment-analysis", model="distilbert-base-uncased-finetuned-sst-2-english")  # Load model
            except Exception as e:
                self.available = False
                self.error = str(e)  # Handle load error
        else:
            self.error = "transformers or matplotlib not installed"  # Dependency error

    def analyze(self, texts):
        if not self.available:
            return []  # Return empty if unavailable
        try:
            results = self.pipeline(texts)  # Run analysis
            return results
        except Exception as e:
            self.error = str(e)  # Handle runtime error
            return []  # Return empty on failure

    def plot_trend(self, sentiments):
        labels = [s['label'] for s in sentiments]  # Get labels
        pos = labels.count('POSITIVE')  # Count positive
        neg = labels.count('NEGATIVE')  # Count negative
        neu = len(labels) - pos - neg  # Calculate neutral
        plt.figure(figsize=(4,3))  # Set figure size
        plt.bar(['Positive', 'Negative', 'Neutral'], [pos, neg, neu], color=['green','red','gray'])  # Create bar chart
        plt.title("Sentiment Distribution")  # Add title
        plt.tight_layout()  # Adjust layout
        from io import BytesIO  # Import for buffer
        buf = BytesIO()  # Create buffer
        plt.savefig(buf, format='png')  # Save to buffer
        plt.close()  # Close plot
        buf.seek(0)  # Reset buffer
        img = Image.open(buf)  # Open as image
        return img  # Return image

def fetch_news_headlines(target):
    headlines = []  # List for headlines
    try:
        url = f"https://www.bing.com/news/search?q={target}&FORM=HDRSC6"  # Build search URL
        resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)  # Fetch page
        soup = BeautifulSoup(resp.text, "html.parser")  # Parse HTML
        for item in soup.select("a.title"):
            text = item.get_text(strip=True)  # Get headline text
            if text:
                headlines.append(text)  # Add to list
        return headlines[:10]  # Return first 10
    except Exception:
        return []  # Return empty on failure

# --- Main Toolkit Class ---
# This class manages the GUI and scan logic for the OSINT toolkit.
class OSINTToolkit:
    def __init__(self, root):
        self.root = root  # Set root window
        self.root.title("Advanced OSINT Toolkit (AI-Powered)")  # Set title
        self.root.geometry("1200x800")  # Set size
        self.set_theme()  # Apply theme
        self.create_gui()  # Build UI
        self.setup_tags()  # Configure text tags
        self.running = False  # Scan status flag
        self.current_target = None  # Current target
        self.scan_history = []  # History list

    def set_theme(self):
        self.root.configure(bg='#2b2b2b')  # Set background
        style = ttk.Style()  # Create style
        style.theme_use('clam')  # Use theme
        style.configure('TFrame', background='#2b2b2b')  # Frame style
        style.configure('TLabel', background='#2b2b2b', foreground='#ffffff')  # Label style
        style.configure('TButton', background='#366dbb', foreground='#ffffff')  # Button style
        style.configure('Accent.TButton', background='#4a90e2', foreground='#ffffff')  # Accent button
        style.map('TButton', background=[('active', '#4a76a8')], foreground=[('active', '#ffffff')])  # Active button
        style.configure('TNotebook', background='#2b2b2b', tabmargins=[2, 5, 2, 0])  # Notebook style
        style.configure('TNotebook.Tab', background='#366dbb', foreground='#ffffff', padding=[10, 2])  # Tab style
        style.map('TNotebook.Tab', background=[('selected', '#4a90e2')], foreground=[('selected', '#ffffff')])  # Selected tab

    def create_gui(self):
        top_frame = ttk.Frame(self.root)  # Top frame
        top_frame.pack(fill='x', padx=10, pady=10)  # Pack frame
        ttk.Label(top_frame, text="Target:").pack(side='left')  # Target label
        self.target_entry = ttk.Entry(top_frame, width=50, font=('Segoe UI', 10))  # Target entry
        self.target_entry.pack(side='left', padx=5)  # Pack entry
        self.scan_btn = ttk.Button(top_frame, text="Start Scan", command=self.start_scan, style='Accent.TButton')  # Scan button
        self.scan_btn.pack(side='left', padx=5)  # Pack button
        ttk.Button(top_frame, text="Clear", command=self.clear_results).pack(side='left')  # Clear button
        ttk.Button(top_frame, text="Save Report", command=self.save_report).pack(side='left', padx=5)  # Save button
        self.notebook = ttk.Notebook(self.root)  # Notebook for tabs
        self.tabs = {}  # Dictionary for tabs
        self.sentiment_graph_label = None  # Graph label for sentiment
        for name in ['Overview', 'Subdomains', 'WHOIS', 'Emails', 'Vulnerabilities', 'Entities', 'Sentiment']:
            frame = ttk.Frame(self.notebook)  # Create frame for tab
            if name == 'Sentiment':
                frame.grid_rowconfigure(0, weight=1)  # Configure row for text
                frame.grid_rowconfigure(1, weight=0)  # Configure row for graph
                frame.grid_columnconfigure(0, weight=1)  # Configure column
                text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, bg='#1e1e1e', fg='#e0e0e0',
                                                insertbackground='white', font=('Consolas', 10))  # Text widget
                text.grid(row=0, column=0, sticky='nsew')  # Grid text
                self.sentiment_graph_label = tk.Label(frame, bg='#1e1e1e')  # Graph label
                self.sentiment_graph_label.grid(row=1, column=0, sticky='nsew', pady=10)  # Grid label
            else:
                text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, bg='#1e1e1e', fg='#e0e0e0',
                                                insertbackground='white', font=('Consolas', 10))  # Text widget for other tabs
                text.pack(fill='both', expand=True)  # Pack text
            self.notebook.add(frame, text=name)  # Add tab
            self.tabs[name] = text  # Store text widget
        self.notebook.pack(fill='both', expand=True, padx=10, pady=(0, 10))  # Pack notebook
        status_frame = ttk.Frame(self.root)  # Status frame
        status_frame.pack(fill='x', side='bottom')  # Pack frame
        self.status_label = ttk.Label(status_frame, text="Ready")  # Status label
        self.status_label.pack(side='left', padx=10)  # Pack label
        self.progress = ttk.Progressbar(status_frame, mode='indeterminate')  # Progress bar
        self.progress.pack(side='right', fill='x', expand=True, padx=10, pady=5)  # Pack bar

    def setup_tags(self):
        for text_widget in self.tabs.values():
            # Configure tags for styled text output
            text_widget.tag_configure('header', font=('Consolas', 12, 'bold'), foreground='#4a90e2')
            text_widget.tag_configure('subheader', font=('Consolas', 11, 'bold'), foreground='#6abfff')
            text_widget.tag_configure('critical', foreground='#ff5252')
            text_widget.tag_configure('high', foreground='#ffa726')
            text_widget.tag_configure('medium', foreground='#ffee58')
            text_widget.tag_configure('low', foreground='#66bb6a')
            text_widget.tag_configure('info', foreground='#42a5f5')
            text_widget.tag_configure('success', foreground='#66bb6a')
            text_widget.tag_configure('entity', foreground='#00e676')

    def clear_results(self):
        for text_widget in self.tabs.values():
            text_widget.delete(1.0, tk.END)  # Clear text
        if self.sentiment_graph_label:
            self.sentiment_graph_label.config(image='')  # Clear graph
        self.update_status("Ready")  # Reset status

    def start_scan(self):
        if self.running:
            return  # Prevent multiple scans
        target = self.target_entry.get().strip()  # Get target
        if not target:
            messagebox.showerror("Error", "Please enter a target domain or IP address")  # Error if empty
            return
        self.running = True  # Set running flag
        self.current_target = target  # Set target
        self.scan_btn.config(text="Scanning...", state='disabled')  # Update button
        self.clear_results()  # Clear previous results
        self.progress.start()  # Start progress
        threading.Thread(target=self.run_scan, args=(target,), daemon=True).start()  # Start scan thread

    def run_scan(self, target):
        try:
            self.update_status(f"Starting comprehensive scan for {target}...")  # Update status
            start_time = datetime.now()  # Record start time
            self.update_tab('Overview', f"OSINT Scan Report for: {target}\n\n", 'header')  # Add header
            self.update_tab('Overview', f"Scan started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n", 'info')  # Add start time

            # Subdomain enumeration section
            self.update_status("Enumerating subdomains...")  # Update status
            self.update_tab('Subdomains', "SUBDOMAIN ENUMERATION\n\n", 'header')  # Add header
            subdomains = self.find_subdomains(target)  # Find subdomains
            self.update_tab('Subdomains', f"Found {len(subdomains)} subdomains:\n\n", 'subheader')  # Add count
            for sub in subdomains:
                self.update_tab('Subdomains', f"• {sub}\n")  # Add each subdomain
            self.update_tab('Overview', f"Subdomains: {len(subdomains)} found\n", 'info')  # Update overview

            # WHOIS lookup and AI-powered analysis section
            self.update_status("Performing WHOIS lookup and AI analysis...")  # Update status
            self.update_tab('WHOIS', "AI-Powered WHOIS Analysis\n\n", 'header')  # Add header
            whois_data = self.get_whois_info(target)  # Get WHOIS data
            raw_whois_text = '\n'.join([f"{k}: {v}" for k, v in whois_data.items() if v]) if isinstance(whois_data, dict) else str(whois_data)  # Format text
            try:
                if SPACY_AVAILABLE and nlp is not None:
                    doc = nlp(raw_whois_text)  # Process with NLP
                    entities = [(ent.text, ent.label_) for ent in doc.ents]  # Extract entities
                    from collections import Counter
                    entity_counts = Counter([ent.label_ for ent in doc.ents])  # Count types
                    summary_lines = [f"Total entities found: {len(entities)}"]  # Build summary
                    for label, count in entity_counts.items():
                        summary_lines.append(f"- {label}: {count}")
                    fallback_result = ai_whois_analysis_fallback(raw_whois_text)  # Fallback analysis
                    summary_lines.append('\nFallback Summary:')
                    summary_lines.append(fallback_result['summary'])
                    risks = fallback_result['risks']  # Get risks
                    recommendations = fallback_result['recommendations']  # Get recommendations
                    self.update_tab('WHOIS', '\n'.join(summary_lines) + '\n\n', 'info')  # Add summary
                    if risks:
                        self.update_tab('WHOIS', "Potential Risks:\n", 'critical')  # Add risks header
                        for risk in risks:
                            self.update_tab('WHOIS', f"- {risk}\n", 'critical')  # Add risks
                    self.update_tab('WHOIS', "\nRecommendations:\n", 'subheader')  # Add recommendations header
                    self.update_tab('WHOIS', recommendations + '\n', 'info')  # Add recommendations
                else:
                    fallback_result = ai_whois_analysis_fallback(raw_whois_text)  # Fallback if no NLP
                    self.update_tab('WHOIS', fallback_result['summary'] + '\n\n', 'info')  # Add summary
                    if fallback_result['risks']:
                        self.update_tab('WHOIS', "Potential Risks:\n", 'critical')  # Add risks header
                        for risk in fallback_result['risks']:
                            self.update_tab('WHOIS', f"- {risk}\n", 'critical')  # Add risks
                    self.update_tab('WHOIS', "\nRecommendations:\n", 'subheader')  # Add recommendations header
                    self.update_tab('WHOIS', fallback_result['recommendations'] + '\n', 'info')  # Add recommendations
            except Exception as e:
                self.update_tab('WHOIS', f"Error in AI WHOIS analysis: {str(e)}\n", 'critical')  # Error handling

            # Email enumeration with AI section
            self.update_status("Generating AI-powered email patterns...")  # Update status
            self.update_tab('Emails', "EMAIL PATTERNS\n\n", 'header')  # Add header
            website_text = ""  # Variable for website text
            try:
                resp = requests.get(f"https://{target}", headers={'User-Agent': 'Mozilla/5.0'}, timeout=10, verify=False)  # Fetch website
                if resp.status_code == 200:
                    if SPACY_AVAILABLE:
                        soup = BeautifulSoup(resp.text, "html.parser")  # Parse HTML
                        website_text = soup.get_text(separator=' ', strip=True)  # Extract text
            except Exception:
                website_text = ""  # Fallback on error
            ai_email = AIEmailModule()  # Instantiate email module
            names = ai_email.extract_names(website_text)  # Extract names
            self.update_tab('Emails', f"Names found on site: {', '.join(names) if names else 'None'}\n", 'info')  # Add names
            generated_emails = ai_email.generate_patterns(names, target)  # Generate patterns
            valid_emails = ai_email.validate_emails(generated_emails)  # Validate
            self.update_tab('Emails', "\nLikely valid email patterns:\n", 'subheader')  # Add header
            for email in valid_emails:
                self.update_tab('Emails', f"• {email}\n", 'info')  # Add emails
            if not valid_emails:
                self.update_tab('Emails', "No likely emails generated from names found on site.\n", 'critical')  # No emails message

            # Vulnerability scanning section
            self.update_status("Scanning for vulnerabilities...")  # Update status
            self.update_tab('Vulnerabilities', "VULNERABILITY SCAN\n\n", 'header')  # Add header
            try:
                vulns = self.scan_vulnerabilities(target)  # Run scan
                if isinstance(vulns, list) and vulns:
                    grouped_vulns = self.group_vulnerabilities_by_severity(vulns)  # Group by severity
                    total_vulns = sum(len(v) for v in grouped_vulns.values())  # Count total
                    self.update_tab('Vulnerabilities', f"Found {total_vulns} potential vulnerabilities\n\n", 'subheader')  # Add count
                    self.update_tab('Overview', f"Vulnerabilities: {total_vulns} potential issues found\n", 'info')  # Update overview
                    for severity, vuln_list in grouped_vulns.items():
                        if not vuln_list:
                            continue  # Skip empty
                        self.update_tab('Vulnerabilities', f"\n{severity.upper()} ({len(vuln_list)})\n", 'subheader')  # Add severity header
                        for v in vuln_list:
                            self.update_tab('Vulnerabilities', f"• {v}\n", severity.lower())  # Add vulnerabilities
                else:
                    self.update_tab('Vulnerabilities', "No vulnerabilities found or scan unsuccessful\n", 'info')  # No vulns message
                    self.update_tab('Overview', "Vulnerabilities: None detected\n", 'info')  # Update overview
            except Exception as e:
                self.update_tab('Vulnerabilities', f"Error during vulnerability scan: {str(e)}\n", 'critical')  # Error handling
                self.update_tab('Overview', "Vulnerabilities: Scan error\n", 'critical')  # Update overview

            # AI-powered Entity Extraction section
            self.update_status("Extracting entities from homepage and fallbacks...")  # Update status
            self.update_tab('Entities', "ENTITY EXTRACTION (AI-POWERED)\n\n", 'header')  # Add header
            try:
                if SPACY_AVAILABLE and nlp is not None:
                    extractor = EntityExtractor()  # Instantiate extractor
                    website_url = target  # Set URL
                    entities = extractor.extract_from_url(website_url, timeout=12)  # Extract
                    if "Error" in entities:
                        self.update_tab('Entities', f"Error: {entities['Error']}\n", 'critical')  # Error message
                    else:
                        total = sum(len(v) for v in entities.values())  # Count total
                        self.update_tab('Entities', f"Found {total} entities in homepage/fallback text\n\n", 'subheader')  # Add count
                        for label, items in entities.items():
                            if items:
                                self.update_tab('Entities', f"{label} ({len(items)}):\n", 'subheader')  # Add label header
                                for item in items:
                                    self.update_tab('Entities', f"• {item}\n", 'entity')  # Add items
                        self.update_tab('Overview', f"Entities: {total} extracted\n", 'info')  # Update overview
                else:
                    self.update_tab('Entities', "Entity extraction requires spaCy and BeautifulSoup.\n", 'critical')  # Dependency message
                    self.update_tab('Entities', "To install dependencies:\n1. pip install spacy beautifulsoup4\n2. python -m spacy download en_core_web_sm\n", 'info')  # Install instructions
                    self.update_tab('Overview', "Entities: Dependencies missing\n", 'critical')  # Update overview
            except Exception as e:
                self.update_tab('Entities', f"Entity extraction error: {str(e)}\n", 'critical')  # Error handling
                self.update_tab('Overview', "Entities: Error during extraction\n", 'critical')  # Update overview

            # Sentiment Analysis section
            self.update_status("Performing sentiment analysis on news...")  # Update status
            self.update_tab('Sentiment', "SENTIMENT & TREND ANALYSIS\n\n", 'header')  # Add header
            headlines = fetch_news_headlines(target)  # Fetch headlines
            if not headlines:
                self.update_tab('Sentiment', "No news headlines found for sentiment analysis.\n", 'critical')  # No headlines message
            else:
                self.update_tab('Sentiment', "Latest headlines:\n", 'subheader')  # Add header
                for h in headlines:
                    self.update_tab('Sentiment', f"- {h}\n", 'info')  # Add each headline
                analyzer = SentimentAnalyzer()  # Instantiate analyzer
                if not analyzer.available:
                    self.update_tab('Sentiment', f"Sentiment analysis unavailable: {analyzer.error}\n", 'critical')  # Unavailable message
                else:
                    results = analyzer.analyze(headlines)  # Run analysis
                    pos = sum(1 for r in results if r['label'] == 'POSITIVE')  # Count positive
                    neg = sum(1 for r in results if r['label'] == 'NEGATIVE')  # Count negative
                    self.update_tab('Sentiment', f"\nPositive: {pos} | Negative: {neg} | Total: {len(results)}\n", 'subheader')  # Add counts
                    img = analyzer.plot_trend(results)  # Generate graph
                    img_tk = ImageTk.PhotoImage(img)  # Convert to Tkinter image
                    self.sentiment_graph_label.config(image=img_tk)  # Set label image
                    self.sentiment_graph_label.image = img_tk  # Keep reference

            end_time = datetime.now()  # Record end time
            duration = (end_time - start_time).total_seconds()  # Calculate duration
            self.update_tab('Overview', f"\nScan completed in {duration:.2f} seconds\n", 'success')  # Add completion
            self.update_status(f"Scan completed in {duration:.2f} seconds")  # Update status
            grouped_vulns = locals().get('grouped_vulns', {})  # Get vulns if defined
            self.scan_history.append({
                'target': target,  # Add to history
                'timestamp': end_time.strftime('%Y-%m-%d %H:%M:%S'),
                'duration': f"{duration:.2f}s",
                'subdomains': len(subdomains),
                'vulns': sum(len(v) for v in grouped_vulns.values()) if grouped_vulns else 0
            })
        except Exception as e:
            self.update_status(f"Error: {str(e)}")  # Update status on error
            messagebox.showerror("Scan Error", str(e))  # Show error message
        finally:
            self.running = False  # Reset running
            self.scan_btn.config(text="Start Scan", state='normal')  # Reset button
            self.progress.stop()  # Stop progress

    def find_subdomains(self, domain):
        results = set()  # Set for unique subdomains
        try:
            session = requests.Session()  # Create session
            session.verify = False  # Disable verify
            adapter = requests.adapters.HTTPAdapter(max_retries=3)  # Retry adapter
            session.mount('http://', adapter)  # Mount adapter
            session.mount('https://', adapter)  # Mount adapter
            response = session.get(f"https://crt.sh/?q=%.{domain}&output=json",
                                   timeout=(5, 10),
                                   headers={'User-Agent': 'Mozilla/5.0 OSINT Tool'})  # Fetch certs
            if response.status_code == 200 and response.text.strip():
                try:
                    data = response.json()  # Parse JSON
                    for entry in data:
                        if 'name_value' in entry:
                            names = entry['name_value'].split('\n')  # Split names
                            for name in names:
                                name = name.strip().lower()  # Clean name
                                if name.endswith(domain) and '*' not in name:
                                    results.add(name)  # Add valid subdomain
                except Exception:
                    pass  # Skip on error
        except requests.exceptions.RequestException as e:
            self.update_tab('Subdomains', f"Certificate lookup failed: {str(e)}\n", 'info')  # Error message
        prefixes = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
            'smtp', 'secure', 'vpn', 'm', 'shop', 'ftp', 'api', 'dev', 'test'
        ]  # Common prefixes
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_sub = {
                executor.submit(self.check_subdomain, f"{p}.{domain}"): p for p in prefixes
            }  # Submit tasks
            for future in concurrent.futures.as_completed(future_to_sub):
                result = future.result()  # Get result
                if result:
                    results.add(result)  # Add if valid
        return sorted(list(results)) if results else [f"www.{domain}"]  # Return sorted or default

    def check_subdomain(self, subdomain):
        try:
            socket.setdefaulttimeout(3)  # Set timeout
            socket.gethostbyname(subdomain)  # Resolve name
            return subdomain  # Return if successful
        except (socket.gaierror, socket.timeout, socket.error):
            return None  # Return None on failure

    def get_whois_info(self, domain):
        if whois is None:
            return {"Error": "Python-whois module not installed. Install with: pip install python-whois"}  # Dependency error
        try:
            info = whois.whois(domain)  # Get WHOIS
            result = {'Domain': domain}  # Start result dict
            for field in ['registrar', 'creation_date', 'expiration_date', 'name_servers', 'emails']:
                value = getattr(info, field, None)  # Get field
                if value:
                    if isinstance(value, list):
                        if len(value) > 0:
                            if isinstance(value[0], str):
                                result[field.title().replace('_', ' ')] = ', '.join(value)  # Join list
                            else:
                                result[field.title().replace('_', ' ')] = str(value[0])  # Convert to string
                    else:
                        result[field.title().replace('_', ' ')] = str(value)  # Add value
            return result  # Return result
        except Exception as e:
            return {"Error": f"WHOIS lookup failed: {str(e)}"}  # Error message

    def scan_vulnerabilities(self, target):
        try:
            if IS_WINDOWS:
                nmap_path = "nmap"  # Windows path
            else:
                nmap_path = "/usr/bin/nmap"  # Linux path
            test_cmd = [nmap_path, "-V"]  # Test command
            subprocess.run(test_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)  # Test nmap
        except:
            self.update_tab('Vulnerabilities', "Nmap not available. Using basic port scan instead.\n\n", 'info')  # Fallback message
            return self.basic_port_scan(target)  # Run basic scan
        try:
            timestamp = int(datetime.now().timestamp())  # Timestamp for file
            xml_file = f"scan_{timestamp}.xml"  # XML file name
            self.update_tab('Vulnerabilities', "Running Nmap vulnerability scan (this may take a few minutes)...\n", 'info')  # Status message
            cmd = [nmap_path, "-sV", "--script", "vuln", "-T4", "-oX", xml_file, target]  # Nmap command
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)  # Run process
            process.communicate()  # Wait for output
            if process.returncode != 0:
                self.update_tab('Vulnerabilities', "Nmap scan failed. Using basic port scan instead.\n", 'info')  # Failure message
                return self.basic_port_scan(target)  # Fallback
            vulns = []  # List for vulns
            if os.path.exists(xml_file):
                try:
                    import xml.etree.ElementTree as ET  # Import XML parser
                    tree = ET.parse(xml_file)  # Parse file
                    root = tree.getroot()  # Get root
                    for host in root.findall('.//host'):
                        for port in host.findall('.//port'):
                            port_id = port.get('portid')  # Get port ID
                            protocol = port.get('protocol')  # Get protocol
                            service_elem = port.find('service')  # Find service
                            if service_elem is not None:
                                service = service_elem.get('name')  # Get service name
                                scripts = port.findall('.//script')  # Find scripts
                                for script in scripts:
                                    if script.get('id') == 'vulners':
                                        output = script.get('output')  # Get output
                                        cve_matches = re.findall(r'(CVE-\d+-\d+).*?(\d+\.\d+)', output)  # Find CVEs
                                        for cve, score in cve_matches:
                                            severity = self.get_severity(float(score))  # Get severity
                                            vulns.append(f"{port_id}/{protocol} ({service}): {cve} (CVSS: {score})")  # Add vuln
                                    elif 'VULNERABLE' in script.get('output', ''):
                                        vulns.append(f"{port_id}/{protocol} ({service}): {script.get('id')}")  # Add vuln
                    os.remove(xml_file)  # Clean up
                except Exception as e:
                    if os.path.exists(xml_file):
                        os.remove(xml_file)  # Clean up on error
                    raise e  # Raise error
            else:
                return ["No vulnerability scan results available"]  # No results message
            return vulns if vulns else ["No vulnerabilities found"]  # Return vulns or message
        except Exception as e:
            return [f"Vulnerability scan error: {str(e)}"]  # Error return

    def basic_port_scan(self, target):
        results = []  # List for results
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389, 8080, 8443]  # Common ports
        try:
            try:
                ip = socket.gethostbyname(target)  # Resolve IP
            except:
                results.append(f"Could not resolve hostname {target}")  # Resolution error
                return results  # Return early
            open_ports = []  # List for open ports
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create socket
                    sock.settimeout(1)  # Set timeout
                    result = sock.connect_ex((ip, port))  # Try connect
                    sock.close()  # Close socket
                    if result == 0:
                        service_name = self.get_service_name(port)  # Get service
                        open_ports.append((port, service_name))  # Add to list
                        severity = "medium" if port in [21, 23, 3306, 3389] else "low"  # Set severity
                        results.append(f"Open port {port} ({service_name})")  # Add result
                except:
                    continue  # Skip on error
            if not open_ports:
                results.append("No open ports found")  # No ports message
            return results  # Return results
        except Exception as e:
            return [f"Port scan error: {str(e)}"]  # Error return

    def get_service_name(self, port):
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 443: "HTTPS", 3306: "MySQL",
            3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }  # Service dictionary
        return services.get(port, "Unknown")  # Return name or unknown

    def get_severity(self, score):
        if score >= 9.0:
            return "critical"  # Critical if high score
        elif score >= 7.0:
            return "high"  # High
        elif score >= 4.0:
            return "medium"  # Medium
        else:
            return "low"  # Low

    def group_vulnerabilities_by_severity(self, vulns):
        groups = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }  # Groups dict
        for v in vulns:
            if "CVE-" in v and "CVSS" in v:
                try:
                    score = float(re.search(r'CVSS: (\d+\.\d+)', v).group(1))  # Extract score
                    severity = self.get_severity(score)  # Get severity
                    groups[severity].append(v)  # Add to group
                except:
                    groups["medium"].append(v)  # Default to medium
            elif "Open port" in v:
                if any(service in v for service in ["FTP", "Telnet", "MySQL", "RDP"]):
                    groups["medium"].append(v)  # Medium for sensitive services
                else:
                    groups["low"].append(v)  # Low otherwise
            else:
                groups["low"].append(v)  # Low default
        return groups  # Return groups

    def save_report(self):
        if not self.current_target:
            messagebox.showerror("Error", "No scan has been performed yet")  # Error if no target
            return
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                initialfile=f"osint_report_{self.current_target}_{datetime.now().strftime('%Y%m%d')}.txt"
            )  # Ask for file path
            if not file_path:
                return  # Cancel if no path
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"OSINT REPORT FOR: {self.current_target}\n")  # Write header
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")  # Write date
                f.write("=" * 60 + "\n\n")  # Separator
                for tab_name, text_widget in self.tabs.items():
                    f.write(f"=== {tab_name.upper()} ===\n")  # Tab header
                    content = text_widget.get(1.0, tk.END)  # Get content
                    f.write(content)  # Write content
                    f.write("\n" + "=" * 60 + "\n\n")  # Separator
                # Include graph description if present
                if self.sentiment_graph_label and self.sentiment_graph_label.image:
                    f.write("=== SENTIMENT GRAPH ===\n")  # Graph header
                    f.write("Sentiment distribution graph included in GUI.\n")  # Description
                    f.write("=" * 60 + "\n\n")  # Separator
            messagebox.showinfo("Success", f"Report saved to {file_path}")  # Success message
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report: {str(e)}")  # Error message

    def update_tab(self, tab_name, text, tag=None):
        text_widget = self.tabs[tab_name]  # Get widget
        if tag:
            text_widget.insert(tk.END, text, tag)  # Insert with tag
        else:
            text_widget.insert(tk.END, text)  # Insert plain
        text_widget.see(tk.END)  # Scroll to end
        self.root.update_idletasks()  # Update UI

    def update_status(self, message):
        self.status_label.config(text=message)  # Set text
        self.root.update_idletasks()  # Update UI

def main():
    try:
        root = tk.Tk()  # Create root
        app = OSINTToolkit(root)  # Instantiate app
        root.mainloop()  # Run loop
    except Exception as e:
        print(f"Error initializing application: {str(e)}")  # Print error
        if tk._default_root:
            tk._default_root.destroy()  # Destroy root
        exit(1)  # Exit

if __name__ == "__main__":
    main()  # Run main