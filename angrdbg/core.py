from .memory import SimSymbolicDbgMemory
from .context import load_project, get_memory_type, set_memory_type, get_debugger, SIMPROCS_FROM_CLE, ONLY_GOT_FROM_CLE, GET_ALL_DISCARD_CLE
from .brk import get_linux_brk
from .got_builder import *

import claripy

try:
    long
    bytes_type = str
except:
    long = int
    bytes_type = bytes


def get_registers():
    project = load_project()
    regs = {}
    
    for reg in sorted(project.arch.registers,
                      key=lambda x: project.arch.registers.get(x)[1]):
        if reg in ("sp", "bp", "ip"):
            continue
        try:
            regs[reg] = debugger.get_reg(reg)
        except BaseException:
            pass
    
    return regs

def StateShot(regs={}, sync_brk=True, check_dbg=False, **kwargs):
    debugger = get_debugger()

    if not check_dbg:
        if not debugger.is_active():
            raise RuntimeError(
                "The debugger must be active and suspended before calling StateShot")
        debugger.refresh_memory()

    project = load_project()

    debugger.before_stateshot()

    mem = SimSymbolicDbgMemory(
        memory_backer=project.loader.memory,
        permissions_backer=None,
        memory_id="mem")

    state = project.factory.blank_state(plugins={"memory": mem}, **kwargs)

    for reg in sorted(project.arch.registers,
                      key=lambda x: project.arch.registers.get(x)[1]):
        if reg in ("sp", "bp", "ip", "pc"):
            continue
        try:
            if reg in regs:
                setattr(state.regs, reg, regs[reg])
            else:
                setattr(state.regs, reg, debugger.get_reg(reg))
            #print(reg, getattr(state.regs, reg), debugger.get_reg(reg))
        except BaseException:
            pass

    if project.simos.name == "Linux":
        # inject code to get brk if we are on linux x86/x86_64
        if sync_brk and project.arch.name in ("AMD64", "X86"):
            state.posix.set_brk(get_linux_brk(project.arch.bits))

        if get_memory_type() == SIMPROCS_FROM_CLE:
            # insert simprocs when possible or resolve the symbol
            state = build_mixed_got(project, state)
        elif get_memory_type() == ONLY_GOT_FROM_CLE:
            # load the entire got from cle with stubs
            state = build_cle_got(project, state)
        elif get_memory_type() == GET_ALL_DISCARD_CLE:
            # angr must not execute loader code so all symbols must be resolved
            state = build_bind_now_got(project, state)

    debugger.after_stateshot(state)
    
    return state


class StateManager(object):
    def __init__(self, state=None):
        self.state = StateShot() if state is None else state
        self.symbolics = {}
        self.debugger = get_debugger()

    def sim(self, key, size=None):
        '''
        key: memory address(int) or register name(str)
        size: size of object in bytes
        '''
        project = load_project()
        if key in project.arch.registers:
            if size is None:
                size = project.arch.registers[key][1]
            size *= 8
            s = claripy.BVS("angrdbg_reg_" + str(key), size)
            setattr(self.state.regs, key, s)
            self.symbolics[key] = (s, size)
        elif isinstance(key, int) or isinstance(key, long):
            if size is None:
                size = project.arch.bits
            else:
                size *= 8
            s = claripy.BVS("angrdbg_mem_" + hex(key), size)
            self.state.memory.store(key, s)
            self.symbolics[key] = (s, size)
        elif isinstance(key, claripy.ast.bv.BV):
            key = self.state.solver.eval(key, cast_to=int)
            self.sim(key, size)
        else:
            raise ValueError(
                "key must be a register name or a memory address, not %s" % str(
                    type(key)))
        return key

    def sim_from_set(self, simset):
        for key in simset.symbolics:
            if key in load_project().arch.registers:
                setattr(self.state.regs, key, simset.symbolics[key][0])
            else:
                self.state.memory.store(key, simset.symbolics[key][0])

    def __getitem__(self, key):
        if key in load_project().arch.registers:
            return getattr(self.state.regs, key)
        elif isinstance(key, int) or isinstance(key, long):
            return self.state.mem[key]
        elif isinstance(key, claripy.ast.bv.BV):
            return self.state.mem[key]
        else:
            raise ValueError("key must be a register name or a memory address")

    def __setitem__(self, key, value):
        if key in load_project().arch.registers:
            setattr(self.state.regs, key, value)
        elif isinstance(key, int) or isinstance(key, long) or isinstance(key, claripy.ast.bv.BV):
            self.state.memory[key] = value
        else:
            raise ValueError("key must be a register name or a memory address")

    def simulation_manager(self):
        return load_project().factory.simulation_manager(self.state)

    def get_symbolic(self, key):
        return self.symbolics.get(key)

    def get_state(self):
        return self.state

    def to_dbg(self, found_state):
        if isinstance(found_state, StateManager):
            return self.to_dbg(found_state.state)
        for key in self.symbolics:
            try:
                if key in load_project().arch.registers:
                    r = found_state.solver.eval(
                        self.symbolics[key][0], cast_to=int)
                    self.debugger.set_reg(key, r)
                else:
                    r = found_state.solver.eval(
                        self.symbolics[key][0], cast_to=bytes_type)
                    self.debugger.put_bytes(key, r)
            except Exception as ee:
                print (" >> failed to write %s to debugger" % key)
                #print ee

    def concretize(self, found_state):
        if isinstance(found_state, StateManager):
            return self.concretize(found_state.state)
        ret = {}
        for key in self.symbolics:
            try:
                if key in load_project().arch.registers:
                    r = found_state.solver.eval(
                        self.symbolics[key][0], cast_to=int)
                    ret[key] = r
                else:
                    r = found_state.solver.eval(
                        self.symbolics[key][0], cast_to=bytes_type)
                    ret[key] = r
            except Exception as ee:
                print (" >> failed to concretize %s" % key)
                #print ee
        return ret

    def print_symbolics(self):
        for key in self.symbolics:
            k = key
            if isinstance(key, int) or isinstance(key, long):
                k = "0x%x" % key
            print ("%s ==> %s" %(str(k), str(self.symbolics[key])))
