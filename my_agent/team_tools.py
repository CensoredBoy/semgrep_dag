
from duckduckgo_search import DDGS

def search_tool(query: str) -> str:
    """Searches the internet for the given query.

    Args:
        query: The search query.

    Returns:
        A formatted string of search results.
    """
    try:
        results = DDGS().text(query, max_results=5)
        if not results:
            return "No results found."
        
        formatted_results = []
        for r in results:
            formatted_results.append(f"Title: {r['title']}\nLink: {r['href']}\nSnippet: {r['body']}\n")
        
        return "\n".join(formatted_results)
    except Exception as e:
        return f"Error performing search: {e}"

def save_report_tool(filename: str, content: str) -> str:
    """Saves the given content to a file.

    Args:
        filename: The name of the file to save (e.g., 'report.md').
        content: The content to write to the file.

    Returns:
        A confirmation message.
    """
    try:
        with open(filename, 'w') as f:
            f.write(content)
        return f"Successfully saved content to {filename}"
    except Exception as e:
        return f"Error saving file: {e}"

import requests
from bs4 import BeautifulSoup

def visit_page_tool(url: str) -> str:
    """Visits a web page and extracts its text content.

    Args:
        url: The URL of the page to visit.

    Returns:
        The text content of the page, or an error message.
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Extract text from p, h1, h2, h3, li tags to allow for structured content
        # We limit the content size to avoid context window issues
        text_elements = []
        for element in soup.find_all(['h1', 'h2', 'h3', 'p', 'li']):
            text = element.get_text(strip=True)
            if text:
                text_elements.append(text)
        
        content = "\n\n".join(text_elements)
        
        # Simple truncation if too long (approx 20k chars)
        if len(content) > 20000:
             content = content[:20000] + "\n...[Content Truncated]"
             
        if not content:
            return "Page visited, but no significant text content found."
            
        return f"Content from {url}:\n\n{content}"
        
    except Exception as e:
        return f"Error visiting page {url}: {e}"
