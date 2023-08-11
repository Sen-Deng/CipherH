from asyncore import file_wrapper    
import angr
import copy
import claripy
from angr import SimProcedure
from plugins import FunStackState
from simulation_procedures import Hook_Taint, Hook_Untaint
from capstone import Cs, CS_ARCH_X86, CS_MODE_64  


f_call_chain = open("/...", 'w+')                                  
f_exec_inf = open("/...", 'w+') 
f_result = open("/...", 'w+') 


project = angr.Project("/.../evaluation_result/openssl_rsa_o3/symbolic_exec/openssl", auto_load_libs=False)
cfg = project.analyses.CFGFast()
cg = project.kb.callgraph
cgv = angr.analyses.forward_analysis.visitors.call_graph.CallGraphVisitor(cg)


k = 0
call_chain = [[] for i in range(99999)]   

for func in cfg.kb.functions:	  
    if cfg.kb.functions[func].name[0:3] != 'sub' and (cfg.kb.functions[func].name[0:1] != '_' or cfg.kb.functions[func].name[0:4] == '_fp_') :
        successors = cgv.successors(cfg.kb.functions[func].addr)
        i = 1
        print(hex(cfg.kb.functions[func].addr), cfg.kb.functions[func].name, k, file=f_call_chain)
        call_chain[k].append(cfg.kb.functions[func].addr)
        call_chain[k].append(cfg.kb.functions[func].name)
        for s in successors:
            if cfg.kb.functions[s].name[0:3] != 'Unr' and cfg.kb.functions[s].name[0:3] != 'sub':
                print(hex(cfg.kb.functions[s].addr),cfg.kb.functions[s].name,i,file=f_call_chain)
                call_chain[k].append(i)
                call_chain[k].append(cfg.kb.functions[s].name)
                i = i + 1
        print("=============================",file=f_call_chain)
        k = k + 1


loop_func = []


traced_func = {}
tainted_func = {}


f2 = open('/.../evaluation/openssl_rsa_o3/tainted_func.txt','r')

for line in f2.readlines():
    line = line.strip()
    key = line.split(':')[0]
    value = line.split(':')[1]
    tainted_func[key] = int(value)

f2.close()

f3 = open('/.../evaluation/openssl_rsa_o3/traced_func.txt','r')

for line in f3.readlines():
    line = line.strip()
    key = line.split(':')[0]
    value = line.split(':')[1]
    traced_func[key] = int(value)

f3.close()





for x in range(0, k):
 
    lop = 0

    if  x>=0:
  
        if call_chain[x][1] in traced_func:

            start_address = call_chain[x][0]
            fun_name = call_chain[x][1]

            for d in range(1, len(call_chain[x])//2):
                if (call_chain[x][2*d + 1] in tainted_func) and (tainted_func[call_chain[x][2*d + 1]] & 2 == 2):
                    lop = 1
                    break

            if (((fun_name in tainted_func) and (tainted_func[fun_name] != 2)) or (lop == 1)):

                print(x,file=f_exec_inf)
                print(fun_name, file=f_exec_inf)
                print("{:x}".format(start_address),file=f_exec_inf)
                project = angr.Project("/.../evaluation/openssl_rsa_o3/symbolic_exec/openssl", auto_load_libs=False)
                initial_state = project.factory.blank_state(addr=start_address) 

                if fun_name in tainted_func:
                    if tainted_func[fun_name] & 128 == 128:
                        initial_state.regs.rdi = initial_state.solver.BVS("k", 64)
                    
                    if tainted_func[fun_name] & 64 == 64:
                        initial_state.regs.rsi = initial_state.solver.BVS("k", 64)

                    if tainted_func[fun_name] & 32 == 32:
                        initial_state.regs.rdx = initial_state.solver.BVS("k", 64)           
                    
                    if tainted_func[fun_name] & 16 == 16:
                       
                        initial_state.regs.rcx = initial_state.solver.BVS("k", 64) 

                    if tainted_func[fun_name] & 8 == 8:
                        initial_state.regs.r8 = initial_state.solver.BVS("k", 64) 

                    if tainted_func[fun_name] & 4 == 4:
                        initial_state.regs.r9 = initial_state.solver.BVS("k", 64) 
    
                def sim_proc(state):
                    state.regs.rax = claripy.BVS('yu', 64)
         

                md = Cs(CS_ARCH_X86, CS_MODE_64)
                for section in project.loader.main_object.sections:
                    if section.is_executable:
                        section_bytes = project.loader.memory.load(
                            section.vaddr, section.memsize)
                        for i in md.disasm(section_bytes, section.vaddr):
                            if i.mnemonic == 'call':
                                if i.mnemonic == 'call' and (i.op_str[0:6] == '0x4004' or i.op_str[0:6] == '0x4005'):               
                                    project.hook(i.address, hook=sim_proc, length=i.size)
            

                for d in range(1, len(call_chain[x])//2):   
                    if (call_chain[x][2*d + 1] in tainted_func) and (tainted_func[call_chain[x][2*d + 1]] & 2 == 2):
                        project.hook_symbol(call_chain[x][2*d + 1], Hook_Taint())    
                    else:
                        project.hook_symbol(call_chain[x][2*d + 1], Hook_Untaint())
                  

                chain = []
                chain_addr = []  
                chain_loop_func = []
               
                se = initial_state.solver.BVV(0x0,64)

                initial_state.register_plugin("ch", FunStackState(chain, chain_addr, chain_loop_func))


                def track_instr(state):          
                    #print("{:x}".format(state.inspect.instruction),file=fw)            
                    global se
                    se = state.regs.rsp


                def track_write_mem_before(state):
                    state.ch.chain_addr = state.ch.chain_addr + [state.inspect.mem_write_address]
                    if (state.solver.eval(state.inspect.mem_write_address - state.regs.rsp) > 1024) and (state.solver.eval(state.regs.rsp - state.inspect.mem_write_address ) > 1024):
                        a = str(state.inspect.mem_write_expr)                   
                        if 'k' in a:
                            print("bug in {} for {:x}".format(fun_name, state.inspect.instruction), file=f_result)
             
                  
                        
                def track_read_mem_before(state):
                    x = 0
                    l = len(state.ch.chain_addr)
                    while l >= 1:
                        l = l-1
                        if state.ch.chain_addr[l] is state.inspect.mem_read_address:
                            x = 1
                            break
                    if x == 0:              
                        a = str(state.inspect.mem_read_address)                    
                        if 'k' in a:
                            state.memory.store(state.inspect.mem_read_address,claripy.BVS('k', state.inspect.mem_read_length*8) , endness = angr.archinfo.Endness.LE, disable_actions=True, inspect=False)
                            state.ch.chain_addr = state.ch.chain_addr + [state.inspect.mem_read_address]
                    

                def track_read_mems(state):
                    x = 0
                    l = len(state.ch.chain_addr)
                    while l >= 1:
                        l = l-1
                        if state.ch.chain_addr[l] is state.inspect.mem_read_address:
                            x = 1
                            break
                    if x == 0:
                        if (state.solver.eval(state.inspect.mem_read_address - state.regs.rsp) > 1024) and (state.solver.eval(state.regs.rsp - state.inspect.mem_read_address ) > 1024):    
                            state.memory.store(state.inspect.mem_read_address,claripy.BVS('k', state.inspect.mem_read_length*8) , endness = angr.archinfo.Endness.LE, disable_actions=True, inspect=False)
                            state.ch.chain_addr = state.ch.chain_addr + [state.inspect.mem_read_address]

               
                initial_state.inspect.b('instruction', action=track_instr)
                initial_state.inspect.b('mem_write', when=angr.BP_BEFORE,action=track_write_mem_before)
                initial_state.inspect.b('mem_read', when=angr.BP_BEFORE, action=track_read_mem_before)

                if (fun_name in tainted_func) and (tainted_func[fun_name] & 1 == 1): 
                    initial_state.inspect.b('mem_read', when=angr.BP_BEFORE, action=track_read_mems)
                    

                simulation = project.factory.simgr(initial_state)
                simulation.use_technique(angr.exploration_techniques.oppologist.Oppologist())
                simulation.use_technique(angr.exploration_techniques.DFS())
                simulation.use_technique(angr.exploration_techniques.loop_seer.LoopSeer(cfg=None, functions=None, loops=None, use_header=False, bound=1, bound_reached=None, discard_stash='spinning', limit_concrete_loops=True))
                simulation.use_technique(angr.exploration_techniques.lengthlimiter.LengthLimiter(1000, drop=False))
                print(simulation.run(),file=f_exec_inf)
            break
                












