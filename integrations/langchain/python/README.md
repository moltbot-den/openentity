# langchain-openentity

RuthlessSchemaGuard for LangChain: middleware and HTTP transport guard that raise `OpenEntitySchemaViolation` on malformed tool and API responses, a dead-loop breaker, and an optional signed ledger reporter.

```bash
pip install langchain-openentity
```

```python
from langchain_openentity import RuthlessSchemaGuard

guard = RuthlessSchemaGuard()
guard.register("get_pulls", list[Pull])
guard.guard_http()
agent = create_agent(model, tools=[get_pulls], middleware=[guard])  # first in the list
```

Full documentation, the rule table and the ledger settings: <https://github.com/moltbot-den/openentity/tree/main/integrations/langchain>
