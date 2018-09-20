# angrdbg

Abstract library to generate angr states from a debugger state

## Install

```
pip install angrdbg
```

## Usage

The library uses an abstract class, `Debugger`, to be agnostic from the debugger api.

The user must implement a derived class, see [abstract_debugger.py](angrdbg/abstract_debugger.py) to view the methods that must be implemented.

After this register an instance of the derived class with the `register_debugger` function.

To create an angr state from the current debugger state use `StateShot`.

## Api

#### StateShot

Return an angr state from the current debug session state.

#### StateManager

A wrapper around angr to simplify the symbolic values creation and to write the results back in the debugger when angr founds a valid path.

##### Methods
+ `instance.sim(key, size)`        create a symbolic value on a register or on a memory address (size is optional)
+ `instance[key]`                  get a register or a memory value
+ `instance.simulation_manager()`  create an angr simulation manager based on the state
+ `instance.to_dbg(found_state)`   transfer to the debugger state the evaluated value of the symbolic value created before with sim

note: memory values are the same that are returned by `state.mem[addr]`

#### Memory type

The memory type defines how angrdbg get the memory from the debugger and from the cle backer. Use `get_memory_type` to know what the active one.

You can change the memory type with `set_memory_type`.

+ `SIMPROCS_FROM_CLE` import only not-stubs simprocedures in the got from the cle backer (defaut)
+ `ONLY_GOT_FROM_CLE` import the entire got from the cle backer
+ `USE_CLE_MEMORY` import memory from the cle backer firstly
+ `GET_ALL_DISCARD_CLE` full debugger memory mode (the only avaiable for PE at the moment)

## Frontends
+ GDB -> [angrgdb](https://github.com/andreafioraldi/angrgdb)
+ IDA Pro debugger -> [IDAngr](https://github.com/andreafioraldi/IDAngr)
+ radare2 -> [r2angrdbg](https://github.com/andreafioraldi/r2angrdbg)
