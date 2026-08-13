import json
from pathlib import Path
import pytest
from opencrl import rollout, get_task
from opencrl.task import discover
from opencrl.models import ScriptedModel

pytestmark = pytest.mark.docker

def test_reference_solution_scores_one():
    discover(Path(__file__).resolve().parent.parent)   # register tasks/ under unique module names
    model = ScriptedModel([
        {"role": "assistant", "content": None,
         "tool_calls": [{"id": "1", "type": "function",
                         "function": {"name": "shell", "arguments": json.dumps(
                             {"command": "rootbash -p -c 'cat /root/flag.txt'"})}}]},
        {"role": "assistant", "content": "Got it: CTF{root_via_suid}",
         "tool_calls": None},
    ])
    r = rollout(get_task("privesc"), model)
    assert r.reward == 1.0
    tool_output = " ".join(
        m.get("content") or "" for m in r.transcript if m.get("role") == "tool")
    assert "CTF{root_via_suid}" in tool_output   # the exploit itself returned the flag, not just the scripted answer
