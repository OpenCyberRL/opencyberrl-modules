# opencyberrl-modules

Community-contributed task modules for [OpenCyberRL](https://github.com/OpenCyberRL/OpenCyberRL).

## Install modules

```bash
opencrl install              # list available modules
opencrl install examples     # install the examples module
opencrl list                 # list installed tasks
```

## Contribute a task

1. Pick or create a module directory (e.g. `examples/`, `cybergym/`).
2. Create a task directory inside it: `examples/my_task/`
3. Write `task.py` and `world.yml` — see the [OpenCyberRL docs](https://github.com/OpenCyberRL/OpenCyberRL) for the Task API.
4. Open a PR.
