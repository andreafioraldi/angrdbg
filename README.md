# angrdbg
Abstract library to generate angr states from a debugger state

# usage

The library uses an abstract class, `Debugger`, to be agnostic from the debugger api.

The user must implement a derived class, see [abstract_debugger.py](angrdbg/abstract_debugger.py) to view the methods that must be implemented.

After this register an instance of the derived class with the `register_debugger` function.

To create an angr state from the current debugger state use `StateShot`.

