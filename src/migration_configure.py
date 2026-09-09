"""Configure a dtk-template build whose split step never mutates project inputs.

Ninja can regenerate itself; the configure rule must retain this adapter too.
The patch lives only in this subprocess and changes generated rules, not sources.
"""
from pathlib import Path
import os
import runpy
import sys


def main():
    root = Path.cwd()
    sys.path.insert(0, str(root))
    from tools import ninja_syntax

    original_rule = ninja_syntax.Writer.rule
    jobs = int(os.environ.get("DTK_MIGRATION_BUILD_JOBS", "4"))
    if jobs < 1:
        raise ValueError("Build jobs must be positive")
    wrapper = str(Path(__file__).resolve()).replace("$", "$$")

    def rule(writer, name, command, *args, **kwargs):
        if name == "split":
            if " dol split " not in command:
                raise RuntimeError("Unsupported dtk-template split rule")
            command = command.replace(" dol split ", f" dol split --no-update -j {jobs} ", 1)
        elif name == "configure":
            if "$python" not in command or "$configure_args" not in command:
                raise RuntimeError("Unsupported dtk-template configure rule")
            command = f'$python "{wrapper}" $configure_args'
        return original_rule(writer, name, command, *args, **kwargs)

    ninja_syntax.Writer.rule = rule
    sys.argv[0] = "configure.py"
    try:
        runpy.run_path(str(root / "configure.py"), run_name="__main__")
    finally:
        ninja_syntax.Writer.rule = original_rule


if __name__ == "__main__":
    main()
