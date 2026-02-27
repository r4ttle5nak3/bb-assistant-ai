"""
Bug Bounty Hunting AI Assistant using LangGraph with OpenRouter
"""

import os
from typing import TypedDict, Annotated
from langgraph.graph import StateGraph, START, END
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
from langchain.chat_models import init_chat_model
import operator
import requests
from pathlib import Path
import json


class AgentState(TypedDict):
    """State object for the agent"""
    messages: Annotated[list[BaseMessage], operator.add]
    program_handle: str
    program_name: str
    program_content: str
    findings: list[str]
    summary: str

def get_hackerone_auth() -> tuple[str, str] | None:
    """Read HackerOne API credentials from .hackerone file.
    
    Expects format: "username:api_token" or just "api_token"
    """
    key_file = Path(".hackerone")
    if key_file.is_file():
        content = key_file.read_text(encoding="utf-8").strip()
        if ":" in content:
            parts = content.split(":", 1)
            return (parts[0], parts[1])
        else:
            return ("api", content)
    return None


def fetch_hackerone_programs(auth: tuple[str, str]) -> list[dict]:
    """Fetch list of HackerOne programs user has access to."""
    url = "https://api.hackerone.com/v1/hackers/programs"
    try:
        response = requests.get(url, auth=auth, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data.get("data", [])
    except requests.RequestException as e:
        print(f"Error fetching programs: {e}")
        return []


def fetch_program_details(handle: str, auth: tuple[str, str]) -> dict | None:
    """Fetch detailed program information including policy and scope."""
    url = f"https://api.hackerone.com/v1/hackers/programs/{handle}"
    try:
        response = requests.get(url, auth=auth, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching program details: {e}")
        return None


def get_llm():
    """Return a LangChain Chat model configured to use OpenRouter.

    Reads API key from env or `.openrouter_api_key` file and then
    constructs a ChatOpenAI instance with OpenRouter's base URL.
    """
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        key_file = Path(".openrouter_api_key")
        if key_file.is_file():
            api_key = key_file.read_text(encoding="utf-8").strip()
            print(f"Loaded OpenRouter API key from {key_file}")

    if not api_key:
        raise ValueError("OpenRouter API key not found. Set OPENROUTER_API_KEY env var or place key in .openrouter_api_key file")

    # initialize ChatOpenAI with OpenRouter settings
    return init_chat_model(
        model="gpt-4o-mini",
        model_provider="openai",
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
        default_headers={
            # optional headers for ranking/sources
            "HTTP-Referer": "bb-assistant-ai",
            "X-OpenRouter-Title": "bb-assistant-ai",
        },
    )




def fetch_hackerone_content(state: AgentState, auth: tuple[str, str]) -> AgentState:
    """Fetch program details via HackerOne API using the program handle."""
    handle = state['program_handle']
    print(f"Fetching program details for: {handle}")

    try:
        program = fetch_program_details(handle, auth)
        if program:
            # Compile program info into readable content
            attrs = program.get("attributes", {})
            content = f"""
Program: {attrs.get('name', handle)}
Handle: {handle}
Policy: {attrs.get('policy', 'N/A')}
Submission State: {attrs.get('submission_state', 'N/A')}
State: {attrs.get('state', 'N/A')}
Offers Bounties: {attrs.get('offers_bounties', False)}
Open Scope: {attrs.get('open_scope', False)}
Currency: {attrs.get('currency', 'N/A')}
"""
            state["program_content"] = content
            print(f"✓ Successfully fetched program details ({len(content)} characters)")
            state["messages"].append(AIMessage(f"Fetched HackerOne program: {handle}"))
        else:
            raise ValueError(f"Could not fetch program details for {handle}")
    except Exception as e:
        error_msg = f"Error fetching program: {str(e)}"
        print(error_msg)
        state["program_content"] = f"Error: {error_msg}"
        state["messages"].append(AIMessage(error_msg))

    return state


def save_summary_to_file(filename: str, summary: AIMessage):
    """Save summary to a markdown file"""
    filepath = Path(filename)
    filepath.write_text(summary.content, encoding='utf-8')
    print(f"✓ Summary saved to: {filepath.absolute()}")



def analyze_target(state: AgentState, llm: OpenRouter) -> AgentState:
    """Analyze the HackerOne program content using LLM"""
    prompt = f"""Analyze the following HackerOne program information and identify:
1. Key vulnerability types they're looking for
2. Scope and assets included
3. Any critical restrictions or out-of-scope items
4. Reward information if available

Program Content:
{state['program_content']}

Provide a structured analysis."""
    
    response = llm.invoke(prompt)
    state["messages"].append(response)
    state["findings"].append(response)
    print(f"\n📊 Analysis:\n{response}")
    return state


def search_vulnerabilities(state: AgentState, llm: OpenRouter) -> AgentState:
    """Extract key program details and generate initial summary using LLM"""
    prompt = f"""Based on this HackerOne program, extract and summarize:
- Program name and scope
- In-scope technologies and platforms
- Vulnerability types accepted
- Exclusions and restrictions
- Key testing guidelines

Program Content:
{state['program_content']}

Format the response as bullet points for clarity."""
    
    response = llm.invoke(prompt)
    state["messages"].append(response)
    state["findings"].append(response)
    print(f"\n📋 Program Details:\n{response}")
    return state


def generate_report(state: AgentState, llm) -> AgentState:
    """Generate a professional markdown summary of the HackerOne program"""
    findings_text = "\n".join([str(f) for f in state["findings"]])
    prompt = f"""Create a professional, well-formatted Markdown summary of a HackerOne bug bounty program.

IMPORTANT: Include COMPLETE and DETAILED Scope information. Do not omit any scope details.

Include these sections:
# HackerOne Program Summary
## Overview
## Scope & Assets
**REQUIRED**: Provide exhaustive details about:
- All in-scope assets (domains, IPs, applications, APIs, Wildcards, etc.)
- Asset types and categories
- Scope limitations and boundaries
- What is explicitly included in scope
- Geographic or jurisdictional scope limits (if any)

## Vulnerability Types Accepted
## Exclusions & Out of Scope
## Reward Structure
## Testing Guidelines
## Key Takeaways

Program Analysis:
{findings_text}

Make it professional, concise, and actionable for security researchers. **Most importantly, do not abbreviate or generalize the Scope & Assets section - include all specific details.**"""
    
    response = llm.invoke(prompt)
    state["messages"].append(response)
    state["summary"] = response
    
    # Save to file
    filename = "hackerone_summary.md"
    save_summary_to_file(filename, response)
    
    print(f"\n📄 Generated Summary:\n{response}")
    return state


def build_agent_graph(llm, auth: tuple[str, str]):
    """Build the LangGraph workflow"""
    workflow = StateGraph(AgentState)
    
    # Add nodes with LLM context through closures
    workflow.add_node("fetch", lambda state: fetch_hackerone_content(state, auth))
    workflow.add_node("analyze", lambda state: analyze_target(state, llm))
    workflow.add_node("extract", lambda state: search_vulnerabilities(state, llm))
    workflow.add_node("summarize", lambda state: generate_report(state, llm))
    
    # Add edges - workflow sequence
    workflow.add_edge(START, "fetch")
    workflow.add_edge("fetch", "analyze")
    workflow.add_edge("analyze", "extract")
    workflow.add_edge("extract", "summarize")
    workflow.add_edge("summarize", END)
    
    # Compile the graph
    return workflow.compile()


def main():
    """Main entry point"""
    print("🚀 Starting HackerOne Program Analyzer with OpenRouter...\n")
    
    # Get HackerOne API auth
    auth = get_hackerone_auth()
    if not auth:
        raise ValueError("HackerOne API credentials not found. Create .hackerone file with 'username:api_token'")
    print("✓ HackerOne API credentials loaded\n")
    
    # Fetch user's programs
    print("Fetching your HackerOne programs...")
    programs = fetch_hackerone_programs(auth)
    if not programs:
        print("No programs found. Make sure your API token is valid.")
        return
    
    # Display programs to user
    print(f"\n📋 Found {len(programs)} program(s):\n")
    for idx, prog in enumerate(programs, 1):
        attrs = prog.get("attributes", {})
        name = attrs.get("name", prog.get("id"))
        handle = attrs.get("handle", "unknown")
        print(f"{idx}. {name} ({handle})")
    print(f"{len(programs) + 1}. 🔍 Search for another program")
    
    # Let user choose
    def find_programs_by_name(programs: list[dict], name: str) -> list[dict]:
        """Return programs whose name contains the search string (case‑insensitive)."""
        name_lower = name.lower()
        return [p for p in programs if name_lower in p.get("attributes", {}).get("name", "").lower()]

    def search_programs_via_hacktivity(query: str, auth: tuple[str, str]) -> list[dict]:
        """Use the hacktivity endpoint to look for programs matching `query`.

        The HackerOne hacktivity API supports a lucene-style `queryString`
        that can filter on related program attributes. We pull out **unique**
        programs from the returned hacktivity items so the caller can present
        choices to the user.
        """
        url = "https://api.hackerone.com/v1/hackers/hacktivity"
        params = {"queryString": query}
        try:
            resp = requests.get(url, auth=auth, params=params, timeout=10)
            resp.raise_for_status()
            items = resp.json().get("data", [])
            programs = []
            seen = set()
            for item in items:
                prog = item.get("relationships", {}).get("program", {}).get("data", {})
                attrs = prog.get("attributes", {})
                handle = attrs.get("handle")
                name = attrs.get("name")
                if handle and handle not in seen:
                    seen.add(handle)
                    programs.append({"attributes": {"handle": handle, "name": name}})
            return programs
        except requests.RequestException as e:
            print(f"Error searching programs via hacktivity: {e}")
            return []

    while True:
        try:
            choice = input(f"\nChoose a program (1-{len(programs) + 1}): ").strip()
            idx = int(choice) - 1
            if 0 <= idx < len(programs):
                selected_program = programs[idx]
                break
            elif idx == len(programs):
                # Search for another program by handle or name
                query = input("Enter program handle or name to search: ").strip()
                if not query:
                    print("Search term cannot be empty.")
                    continue

                hack_matches = search_programs_via_hacktivity(query, auth)
                print("Programs found via hacktivity search:")
                for hi, prog in enumerate(hack_matches, 1):
                    attrs = prog.get("attributes", {})
                    print(f"{hi}. {attrs.get('name')} ({attrs.get('handle')})")
                sel = input(f"Choose one (1-{len(hack_matches)}) or press enter to continue treating '{query}' as a handle: ").strip()
                if sel.isdigit():
                    sel_idx = int(sel) - 1
                    if 0 <= sel_idx < len(hack_matches):
                        selected_program = hack_matches[sel_idx]
                        print(f"Selected program {selected_program.get('attributes', {}).get('name')} from hacktivity results")
                        break

                # if not found by any of the above, try direct handle lookup
                print(f"\nSearching for program by handle: {query}...")
                search_result = fetch_program_details(query, auth)
                if search_result and "data" in search_result:
                    selected_program = search_result["data"]
                    break
                else:
                    print(f"Program '{query}' not found or you don't have access.")
                    continue
            else:
                print(f"Please enter a number between 1 and {len(programs) + 1}")
        except ValueError:
            print("Invalid input. Please enter a number.")
    
    program_handle = selected_program["attributes"]["handle"]
    program_name = selected_program["attributes"]["name"]
    
    # Initialize OpenRouter LLM
    llm = get_llm()
    print("\n✓ OpenRouter LLM initialized\n")
    
    # Build agent graph
    agent = build_agent_graph(llm, auth)
    
    # Initialize state
    initial_state = {
        "messages": [HumanMessage(content=f"Analyze HackerOne program: {program_name}")],
        "program_handle": program_handle,
        "program_name": program_name,
        "program_content": "",
        "findings": [],
        "summary": ""
    }
    
    print(f"🔍 Analyzing: {program_name} ({program_handle})\n")
    print("=" * 60)
    
    result = agent.invoke(initial_state)
    
    print("=" * 60)
    print(f"\n✓ Analysis complete!")
    print(f"✓ Summary saved to: hackerone_summary.md")


if __name__ == "__main__":
    main()
