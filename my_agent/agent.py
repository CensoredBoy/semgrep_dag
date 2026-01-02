from google.adk.agents.llm_agent import Agent
from google.adk.models.registry import LLMRegistry
from extended_lite_llm import ExtendedLiteLlm
from team_tools import search_tool, save_report_tool, visit_page_tool

# Initialize agent with Extended LiteLlm support
try:
    LLMRegistry.register(ExtendedLiteLlm)
except Exception as e:
    # It might be registered already in some contexts
    pass

# ---- Define Agents ----

# 1. Researcher Agent
researcher_agent = Agent(
    model='ollama/qwen2.5',
    name='researcher',
    description='Specialist in finding information on the internet.',
    instruction=(
        "You are a cybersecurity researcher. Your goal is to find accurate and relevant "
        "information about CVEs, MLSecOps practices, and other security topics. "
        "Use the search_tool to find pages, and then use the visit_page_tool to read "
        "the content of promising pages to get detailed information. "
        "Provide detailed summaries of your findings based on the actual page content."
    ),
    tools=[search_tool, visit_page_tool]
)

# 2. Writer Agent
writer_agent = Agent(
    model='ollama/qwen2.5',
    name='writer',
    description='Specialist in compiling research into markdown reports.',
    instruction=(
        "You are a technical writer. You receive research findings and compile them into "
        "a well-structured Markdown report. Use available methods to save the report to a file "
        "if requested, or just output the markdown content."
    ),
    tools=[save_report_tool]
)

# 3. Manager Agent (Root)
root_agent = Agent(
    model='ollama/qwen2.5',
    name='cyber_security_manager',
    description='Manager of the cybersecurity research team.',
    instruction=(
        "You are the manager of a cybersecurity research team. "
        "1. Understand the user's research request. "
        "2. Delegate research tasks to the 'researcher' agent. "
        "3. Once information is gathered, delegate the writing task to the 'writer' agent. "
        "4. Ensure the final report is comprehensive and saved."
    ),
    sub_agents=[researcher_agent, writer_agent]
)
