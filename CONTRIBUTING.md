# Contributing

Thank you for contributing a task module to OpenCyberRL!

## 1. Clone the repo

```bash
git clone https://github.com/OpenCyberRL/opencyberrl-modules.git
cd opencyberrl-modules
```

## 2. Add a task directory

Pick or create a module directory (e.g. `examples/`, `cybergym/`), then add a
sub-directory for your task:

```
examples/my_task/
├── task.py      # Task class implementing the OpenCyberRL Task API
└── world.yml    # world definition (images, networks, flags, etc.)
```

- `task.py` must define a `Task` subclass with `reset()` and `step()` and the
  reward/termination logic for your scenario.
- `world.yml` describes the containerised environment. See the
  [OpenCyberRL docs](https://github.com/OpenCyberRL/OpenCyberRL) for the schema.

## 3. Test with opencrl

```bash
opencrl run examples/my_task        # run the task end-to-end
opencrl list                        # confirm your task is discovered
pytest examples/my_task/test_task.py # run the task's own unit tests
```

Make sure your task passes before opening a PR.

## 4. Open a PR

Commit your changes on a feature branch and open a pull request against the
`main` branch. Include a short description of the task scenario and how to run
it.
