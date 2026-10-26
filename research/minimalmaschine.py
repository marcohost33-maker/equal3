"""One-instruction SUBLEQ educational VM with German step explanations.
Finite bounded demonstration only; NOT a proof of Turing completeness.
"""
from dataclasses import dataclass

class MachineError(ValueError):
    pass

@dataclass(frozen=True)
class Trace:
    pc: int
    instruction: tuple[int,int,int]
    before: int
    after: int
    next_pc: int
    deutsch: str


def execute(program, memory, *, max_steps=10000, max_cells=4096, max_abs_value=(1<<63)-1):
    """Execute SUBLEQ (a,b,c): mem[b] -= mem[a]; branch c if <=0, else pc+1.
    c=-1 halts. Falling beyond program halts. No I/O; bounds are deliberate.
    """
    if not isinstance(memory, (tuple,list)) or not 0<len(memory)<=max_cells or not all(type(x) is int for x in memory):
        raise MachineError('invalid fixed-length integer memory')
    if not isinstance(program, (tuple,list)) or not program or len(program)>10000:
        raise MachineError('invalid program length')
    if type(max_steps) is not int or not 1<=max_steps<=1000000:
        raise MachineError('invalid step budget')
    if any(abs(x)>max_abs_value for x in memory):
        raise MachineError('initial memory outside numerical bound')
    instr=[]
    for t in program:
        if not isinstance(t,(tuple,list)) or len(t)!=3 or not all(type(v) is int for v in t):
            raise MachineError('instruction must be three integer indices')
        a,b,c=t
        if not 0<=a<len(memory) or not 0<=b<len(memory) or not -1<=c<len(program):
            raise MachineError('invalid address or jump target')
        instr.append((a,b,c))
    mem=list(memory)
    pc=0
    trace=[]
    for _ in range(max_steps):
        if pc==-1 or pc>=len(instr):
            return tuple(mem), tuple(trace)
        a,b,c=instr[pc]
        before=mem[b]
        after=before-mem[a]
        if abs(after)>max_abs_value:
            raise MachineError('numerical bound exceeded')
        mem[b]=after
        next_pc=c if after<=0 else pc+1
        desc=(f'Speicherstelle {a} ({mem[a] if a!=b else before}) von Zelle {b} ({before}) '
              f'abziehen; Ergebnis {after}. ' +
              (f'Da das Ergebnis <= 0 ist, gehe zu Befehl {c}.' if after<=0 else
               f'Da das Ergebnis > 0 ist, gehe zum nächsten Befehl {next_pc}.'))
        trace.append(Trace(pc,(a,b,c),before,after,next_pc,desc))
        pc=next_pc
    raise MachineError('step budget exhausted: probable loop / nontermination')
