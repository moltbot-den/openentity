# langchain-openentity

RuthlessSchemaGuard for LangChain: middleware and HTTP transport guard that raise `OpenEntitySchemaViolation` on malformed tool and API responses, a dead-loop breaker, and an optional signed ledger reporter.

```bash
pip install langchain-openentity
```

```python
import httpx
from langchain.agents import create_agent
from langchain_core.tools import tool
from langchain_openentity import RuthlessSchemaGuard
from pydantic import BaseModel

class Pull(BaseModel):
    number: int
    title: str

@tool
def get_pulls(repo: str) -> str:
    """List open pull requests of a GitHub repo."""
    return httpx.get(f"https://api.github.com/repos/{repo}/pulls", headers={"Accept": "application/json"}).text

guard = RuthlessSchemaGuard()
guard.register("get_pulls", list[Pull])
guard.guard_http()
agent = create_agent("anthropic:claude-sonnet-4-6", tools=[get_pulls], middleware=[guard])  # first in the list
```

Full documentation, the rule table and the ledger settings: <https://github.com/moltbot-den/openentity/tree/main/integrations/langchain>
