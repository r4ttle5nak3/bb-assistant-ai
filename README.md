# bb-assistant-ai

An intelligent AI-powered assistant for bug bounty hunting that leverages the HackerOne API and LLM-driven analysis to help researchers identify and understand vulnerability scopes.

## Overview

This tool automates the tedious task of analyzing HackerOne bug bounty programs by:
- Fetching program details from the HackerOne API
- Using an LLM (via OpenRouter) to analyze scope, vulnerability types, and restrictions
- Generating professional, well-structured Markdown reports
- Enabling smart program discovery through multiple search methods

## Features

### 🎯 Multi-Method Program Discovery
- **Direct List**: Browse programs you have access to
- **Name Search**: Filter locally available programs by name (case-insensitive)
- **Hacktivity Search**: Use the HackerOne Hacktivity endpoint to discover programs by their appearance in disclosed reports
- **Handle Lookup**: Direct lookup by program handle via API

### 📊 Intelligent Analysis Workflow
1. **Fetch** - Retrieve detailed program information (policy, scope, state)
2. **Analyze** - LLM identifies key vulnerability types, scope, restrictions
3. **Extract** - Structured extraction of program details and guidelines
4. **Summarize** - Generate professional Markdown reports with complete scope details
5. **Review** - The agent validates the generated summary to ensure all required
   sections are present and that any structured scope data is rendered as a
   Markdown table (the agent will flag missing elements before finishing).

### 📄 Report Generation
- Comprehensive program summaries with sections for:
  - Overview
  - Scope & Assets (exhaustive detail)
  - Vulnerability Types Accepted
  - Exclusions & Out of Scope
  - Reward Structure
  - Testing Guidelines
  - Key Takeaways
- Automatically saved to `hackerone_summary.md`

### 🔎 Structured Scope Support

- If structured scope data is available for a program, the agent will include
   it in the generated report in a concise, tabular form.

## Requirements

- Python 3.10+
- HackerOne API credentials
- OpenRouter API key

## Setup

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Create `.hackerone` file** with your HackerOne credentials:
   ```
   username:api_token
   ```

3. **Set OpenRouter API key** via environment variable:
   ```bash
   export OPENROUTER_API_KEY="your-key-here"
   ```
   Or create `.openrouter_api_key` file with your key.

## Usage

```bash
python main.py
```

The script will:
1. Load your HackerOne credentials
2. Display available programs
3. Prompt you to select a program (or search by name/handle)
4. Analyze the program with the LLM
5. Generate and save a summary to `hackerone_summary.md`

Additional behaviors:

- The agent runs a final review of the generated summary and will print or
   append messages indicating whether the report meets the formatting and
   completeness requirements.

## Architecture

Built with:
- **LangGraph**: Workflow orchestration for multi-stage analysis
- **LangChain**: LLM integration and message handling
- **OpenRouter**: Access to `gpt-4o-mini` for cost-effective analysis
- **HackerOne API**: Program and activity data retrieval

## Project Status

This is a proof-of-concept (PoC) demonstrating how AI agents can assist security researchers in understanding bug bounty program scope and requirements more efficiently.
