from asyncore import file_wrapper    
import angr
import copy
import claripy
from angr import SimProcedure
from plugins import FunStackState
from simulation_procedures import Hook_Taint, Hook_Untaint
from capstone import Cs, CS_ARCH_X86, CS_MODE_64  

#set your own output file
f_call_chain = open("/.../...", 'w+')                                  
f_exec_inf = open("/.../...", 'w+') 
f_result = open("/.../...", 'w+') 


project = angr.Project("/.../evaluation_result/wolfssl_rsa_o2/symbolic_exec/wolfssl", auto_load_libs=False)
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


f2 = open('/.../evaluation_result/wolfssl_rsa_o2/tainted_func.txt','r')

for line in f2.readlines():
    line = line.strip()
    key = line.split(':')[0]
    value = line.split(':')[1]
    tainted_func[key] = int(value)

f2.close()

f3 = open('/.../evaluation_result/wolfssl_rsa_o2/traced_func.txt','r')

for line in f3.readlines():
    line = line.strip()
    key = line.split(':')[0]
    value = line.split(':')[1]
    traced_func[key] = int(value)

f3.close()





for x in range(0, k):
 
    lop = 0
    #set timeout functions
    if  x>=0 and x != 47 and x != 49 and x != 260:
  
        if call_chain[x][1] in traced_func:

            start_address = call_chain[x][0]
            fun_name = call_chain[x][1]

            for d in range(1, len(call_chain[x])//2):
                if (call_chain[x][2*d + 1] in tainted_func) and (tainted_func[call_chain[x][2*d + 1]] & 2 == 2):
                    lop = 1
                    break

            if (((fun_name in tainted_func) and (tainted_func[fun_name] != 2)) or (lop == 1)):

                print(x, file=f_exec_inf)
                print(fun_name, file=f_exec_inf)
                print("{:x}".format(start_address),file=f_exec_inf)
                project = angr.Project("/.../evaluation_result/wolfssl_rsa_o2/symbolic_exec/wolfssl", auto_load_libs=False)
                initial_state = project.factory.blank_state(addr=start_address) 

                if fun_name in tainted_func:
                    if tainted_func[fun_name] & 128 == 128:
                        initial_state.regs.rdi = initial_state.solver.BVS("kp", 64)
                    
                    if tainted_func[fun_name] & 64 == 64:
                        initial_state.regs.rsi = initial_state.solver.BVS("kp", 64)

                    if tainted_func[fun_name] & 32 == 32:
                        initial_state.regs.rdx = initial_state.solver.BVS("kp", 64)           
                    
                    if tainted_func[fun_name] & 16 == 16:
                        initial_state.regs.rcx = initial_state.solver.BVS("kp", 64) 

                    if tainted_func[fun_name] & 8 == 8:
                        initial_state.regs.r8 = initial_state.solver.BVS("kp", 64) 

                    if tainted_func[fun_name] & 4 == 4:
                        initial_state.regs.r9 = initial_state.solver.BVS("kp", 64) 


                def sim_proc(state):
                    state.regs.rax = claripy.BVS('u', 64)
         

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
                        # print("tainted return-value",file=f_exec_inf)
                    else:
                        project.hook_symbol(call_chain[x][2*d + 1], Hook_Untaint())
                        # print("untainted return-vaule",file=f_exec_inf)


                chain = []
                chain_addr = []  
                chain_loop_func = []
        
                se = initial_state.solver.BVV(0x0,64)

                initial_state.register_plugin("ch", FunStackState(chain, chain_addr, chain_loop_func))

                def track_instr(state):
                    global se
                    se = state.regs.rsp


                def track_write_mem_before(state):

                    state.ch.chain_addr = state.ch.chain_addr + [state.inspect.mem_write_address]

                    l = len(state.ch.chain)//4
                    while l >= 1:
                        l = l - 1
                        if state.ch.chain[4*l+1] is state.inspect.mem_write_address:
                           
                            a = str(state.inspect.mem_write_expr)
                            b = a[3:5]
                            if (state.ch.chain[4*l+2] == b) and ((('kp' in str(state.ch.chain[4*l+3])) and ('kp' in a)) or (('kl' in str(state.ch.chain[4*l+3])) and ('kl' in a)) or (('kr' in str(state.ch.chain[4*l+3])) and ('kr' in a))):
                                          
                                if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr]) and state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] != state.inspect.mem_write_expr]):
                                
                                    resv = ('BVS',  'Concat',  'Extract') 
                                    temp1 =  state.ch.chain[4*l+3].op
                                    temp2 =  state.inspect.mem_write_expr.op

                                    if temp1 in resv and temp2 in resv:
                                        temp3 = state.solver.BVS("sol",  int(b))
                                        temp4 = state.solver.BVS("sol",  int(b))                                 
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)

                                    if  temp1 == '__add__' and temp2  in resv:
                                        if 'k' in str(state.ch.chain[4*l+3].args[0]):
                                            temp3 = state.ch.chain[4*l+3] - state.ch.chain[4*l+3].args[0] + state.solver.BVS("sol",  int(b))
                                        else:
                                            temp3 = state.ch.chain[4*l+3] - state.ch.chain[4*l+3].args[1] + state.solver.BVS("sol",  int(b))
                                        temp4 = state.solver.BVS("sol",  int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)

                                    if  temp1  in resv and temp2 == '__add__' :
                                        if 'k' in str(state.inspect.mem_write_expr.args[0]):
                                            temp4 = state.inspect.mem_write_expr - state.inspect.mem_write_expr.args[0] + state.solver.BVS("sol",  int(b))
                                        else:
                                             temp4 = state.inspect.mem_write_expr - state.inspect.mem_write_expr.args[1] + state.solver.BVS("sol",  int(b))
                                        temp3 = state.solver.BVS("sol",  int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)        

                                    if  temp1 == '__add__' and temp2 ==  '__add__' :
                                        if 'k' in str(state.ch.chain[4*l+3].args[0]):
                                            temp3 = state.ch.chain[4*l+3] - state.ch.chain[4*l+3].args[0] + state.solver.BVS("sol",  int(b))
                                        else:
                                            temp3 = state.ch.chain[4*l+3] - state.ch.chain[4*l+3].args[1] + state.solver.BVS("sol",  int(b))                                       
                                        if 'k' in str(state.inspect.mem_write_expr.args[0]):
                                            temp4 = state.inspect.mem_write_expr - state.inspect.mem_write_expr.args[0] + state.solver.BVS("sol",  int(b))
                                        else:
                                             temp4 = state.inspect.mem_write_expr - state.inspect.mem_write_expr.args[1] + state.solver.BVS("sol",  int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)                     
                              
                                    if  temp1 == '__xor__' and temp2  in resv:
                                        if 'k' in str(state.ch.chain[4*l+3].args[0]):
                                            temp3 = state.ch.chain[4*l+3] ^ state.ch.chain[4*l+3].args[0] ^ state.solver.BVS("sol", int(b))
                                        else:
                                            temp3 = state.ch.chain[4*l+3] ^ state.ch.chain[4*l+3].args[1] ^ state.solver.BVS("sol", int(b))
                                        temp4 = state.solver.BVS("sol", int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)

                                    if  temp1  in resv and temp2 == '__xor__' :
                                        if 'k' in str(state.inspect.mem_write_expr.args[0]):
                                            temp4 = state.inspect.mem_write_expr ^ state.inspect.mem_write_expr.args[0] ^ state.solver.BVS("sol",  int(b))
                                        else:
                                             temp4 = state.inspect.mem_write_expr ^ state.inspect.mem_write_expr.args[1] ^ state.solver.BVS("sol",  int(b))
                                        temp3 = state.solver.BVS("sol",  int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)        

                                    if  temp1 == '__xor__' and temp2 ==  '__xor__' :
                                        if 'k' in str(state.ch.chain[4*l+3].args[0]):
                                            temp3 = state.ch.chain[4*l+3] ^ state.ch.chain[4*l+3].args[0] ^ state.solver.BVS("sol",  int(b))
                                        else:
                                            temp3 = state.ch.chain[4*l+3] ^ state.ch.chain[4*l+3].args[1] ^ state.solver.BVS("sol",  int(b))                                       
                                        if 'k' in str(state.inspect.mem_write_expr.args[0]):
                                            temp4 = state.inspect.mem_write_expr ^ state.inspect.mem_write_expr.args[0] ^ state.solver.BVS("sol",  int(b))
                                        else:
                                             temp4 = state.inspect.mem_write_expr ^ state.inspect.mem_write_expr.args[1] ^ state.solver.BVS("sol",  int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)                      
                                                            
                                    if  temp1 == '__invert__' and temp2  in resv:                                     
                                        temp3 = ~state.solver.BVS("sol", int(b))
                                        temp4 = state.solver.BVS("sol", int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)

                                    if  temp1  in resv and temp2 == '__invert__' :
                                        temp3 = state.solver.BVS("sol",  int(b))
                                        temp4 = ~state.solver.BVS("sol", int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)        

                                    if  temp1 == '__invert__' and temp2 ==  '__invert__' :
                                        temp3 = ~state.solver.BVS("sol",  int(b))
                                        temp4 = ~state.solver.BVS("sol", int(b))                     
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)        

                                    if  temp1 == '__or__' and temp2  in resv:
                                        if 'k' in str(state.ch.chain[4*l+3].args[0]):
                                            temp3 = state.ch.chain[4*l+3] & state.ch.chain[4*l+3].args[1] | state.solver.BVS("sol", int(b))
                                        else:
                                            temp3 = state.ch.chain[4*l+3] & state.ch.chain[4*l+3].args[0] | state.solver.BVS("sol", int(b))
                                        temp4 = state.solver.BVS("sol", int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)

                                    if  temp1 == '__or__' and temp2  == '__invert__':
                                        if 'k' in str(state.ch.chain[4*l+3].args[0]):
                                            temp3 = state.ch.chain[4*l+3] & state.ch.chain[4*l+3].args[1] | state.solver.BVS("sol", int(b))
                                        else:
                                            temp3 = state.ch.chain[4*l+3] & state.ch.chain[4*l+3].args[0] | state.solver.BVS("sol", int(b))
                                        temp4 = ~state.solver.BVS("sol", int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)

                                    if  temp1  in resv and temp2 == '__or__' :
                                        if 'k' in str(state.inspect.mem_write_expr.args[0]):
                                            temp4 = state.inspect.mem_write_expr & state.inspect.mem_write_expr.args[1] | state.solver.BVS("sol",  int(b))
                                        else:
                                            temp4 = state.inspect.mem_write_expr & state.inspect.mem_write_expr.args[0] | state.solver.BVS("sol",  int(b))
                                        temp3 = state.solver.BVS("sol",  int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)        

                                    if  temp1 == '__or__' and temp2 ==  '__or__' :
                                        if 'k' in str(state.ch.chain[4*l+3].args[0]):
                                            temp3 = state.ch.chain[4*l+3] & state.ch.chain[4*l+3].args[1] | state.solver.BVS("sol",  int(b))
                                        else:
                                            temp3 = state.ch.chain[4*l+3] & state.ch.chain[4*l+3].args[0] | state.solver.BVS("sol",  int(b))                                       
                                        if 'k' in str(state.inspect.mem_write_expr.args[0]):
                                            temp4 = state.inspect.mem_write_expr & state.inspect.mem_write_expr.args[1] | state.solver.BVS("sol",  int(b))
                                        else:
                                             temp4 = state.inspect.mem_write_expr & state.inspect.mem_write_expr.args[0] | state.solver.BVS("sol",  int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)        
                                                                                        
                                    if  temp1 == '__sub__' and temp2  in resv:
                                        if 'k' in str(state.ch.chain[4*l+3].args[0]):
                                            temp3 = state.ch.chain[4*l+3] - state.ch.chain[4*l+3].args[0] +  state.solver.BVS("sol",  int(b))
                                        else:
                                            temp3 = state.ch.chain[4*l+3] + state.ch.chain[4*l+3].args[1] - state.solver.BVS("sol",  int(b))
                                        temp4 = state.solver.BVS("sol",  int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)

                                    if  temp1  in resv and temp2 == '__sub__' :
                                        if 'k' in str(state.inspect.mem_write_expr.args[0]):
                                            temp4 = state.inspect.mem_write_expr - state.inspect.mem_write_expr.args[0] + state.solver.BVS("sol",  int(b))
                                        else:
                                             temp4 = state.inspect.mem_write_expr + state.inspect.mem_write_expr.args[1] - state.solver.BVS("sol",  int(b))
                                        temp3 = state.solver.BVS("sol",  int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)        

                                    if  temp1 == '__sub__' and temp2 ==  '__sub__' :
                                        if 'k' in str(state.ch.chain[4*l+3].args[0]):
                                            temp3 = state.ch.chain[4*l+3] - state.ch.chain[4*l+3].args[0] + state.solver.BVS("sol",  int(b))
                                        else:
                                            temp3 = state.ch.chain[4*l+3] + state.ch.chain[4*l+3].args[1] - state.solver.BVS("sol",  int(b))                                       
                                        if 'k' in str(state.inspect.mem_write_expr.args[0]):
                                            temp4 = state.inspect.mem_write_expr - state.inspect.mem_write_expr.args[0] + state.solver.BVS("sol",  int(b))
                                        else:
                                             temp4 = state.inspect.mem_write_expr + state.inspect.mem_write_expr.args[1] - state.solver.BVS("sol",  int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)        
                                        
                                    if  temp1 == '__mul__' and temp2  in resv:
                                        if 'k' in str(state.ch.chain[4*l+3].args[0]):  
                                            temp3 = state.ch.chain[4*l+3] / state.ch.chain[4*l+3].args[0] * state.solver.BVS("sol",  int(b))
                                        else:
                                            temp3 = state.ch.chain[4*l+3] / state.ch.chain[4*l+3].args[1] * state.solver.BVS("sol",  int(b))
                                        temp4 = state.solver.BVS("sol",  int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)

                                    if  temp1  in resv and temp2 == '__mul__' :
                                        if 'k' in str(state.inspect.mem_write_expr.args[0]): 
                                            temp4 = state.inspect.mem_write_expr / state.inspect.mem_write_expr.args[0] * state.solver.BVS("sol",  int(b))
                                        else:
                                            temp4 = state.inspect.mem_write_expr / state.inspect.mem_write_expr.args[1] * state.solver.BVS("sol",  int(b))
                                        temp3 = state.solver.BVS("sol",  int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)        

                                    if  temp1 == '__mul__' and temp2 ==  '__mul__' :
                                        if 'k' in str(state.ch.chain[4*l+3].args[0]):
                                            temp3 = state.ch.chain[4*l+3] / state.ch.chain[4*l+3].args[0] * state.solver.BVS("sol",  int(b))
                                        else:
                                            temp3 = state.ch.chain[4*l+3] / state.ch.chain[4*l+3].args[1] * state.solver.BVS("sol",  int(b))                                       
                                        if 'k' in str(state.inspect.mem_write_expr.args[0]):
                                            temp4 = state.inspect.mem_write_expr / state.inspect.mem_write_expr.args[0] * state.solver.BVS("sol",  int(b))
                                        else:
                                             temp4 = state.inspect.mem_write_expr / state.inspect.mem_write_expr.args[1] * state.solver.BVS("sol",  int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)        
                                        
                                    if  temp1 == '__div__' and temp2  in resv:
                                        if 'k' in str(state.ch.chain[4*l+3].args[0]):
                                            temp3 = state.ch.chain[4*l+3] / state.ch.chain[4*l+3].args[0] * state.solver.BVS("sol",  int(b))
                                        else:
                                            temp3 = state.ch.chain[4*l+3] * state.ch.chain[4*l+3].args[1] / state.solver.BVS("sol",  int(b))
                                        temp4 = state.solver.BVS("sol",  int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)

                                    if  temp1  in resv and temp2 == '__div__' :
                                        if 'k' in str(state.inspect.mem_write_expr.args[0]):
                                            temp4 = state.inspect.mem_write_expr / state.inspect.mem_write_expr.args[0] * state.solver.BVS("sol",  int(b))
                                        else:
                                             temp4 = state.inspect.mem_write_expr * state.inspect.mem_write_expr.args[1] / state.solver.BVS("sol",  int(b))
                                        temp3 = state.solver.BVS("sol",  int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)        

                                    if  temp1 == '__div__' and temp2 ==  '__div__' :
                                        if 'k' in str(state.ch.chain[4*l+3].args[0]):
                                            temp3 = state.ch.chain[4*l+3] / state.ch.chain[4*l+3].args[0] * state.solver.BVS("sol",  int(b))
                                        else:
                                            temp3 = state.ch.chain[4*l+3] * state.ch.chain[4*l+3].args[1] / state.solver.BVS("sol",  int(b))                                       
                                        if 'k' in str(state.inspect.mem_write_expr.args[0]):
                                            temp4 = state.inspect.mem_write_expr / state.inspect.mem_write_expr.args[0] * state.solver.BVS("sol",  int(b))
                                        else:
                                             temp4 = state.inspect.mem_write_expr * state.inspect.mem_write_expr.args[1] / state.solver.BVS("sol",  int(b))
                                        if state.solver.satisfiable(extra_constraints=[state.ch.chain[4*l+3] == state.inspect.mem_write_expr, temp3 != temp4]):
                                            print("bug in {} for {:x} and {:x}".format(fun_name, state.ch.chain[4*l], state.inspect.instruction), file=f_result)                             
                       
                            break

                    state.ch.chain = state.ch.chain + [state.inspect.instruction]
                    state.ch.chain = state.ch.chain + [state.inspect.mem_write_address]
                    a = str(state.inspect.mem_write_expr)
                    b = a[3:5]
                    state.ch.chain = state.ch.chain + [b]
                    state.ch.chain = state.ch.chain + [state.inspect.mem_write_expr]

                        

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
                        if 'kp' in a:
                            state.memory.store(state.inspect.mem_read_address,claripy.BVS('kp', state.inspect.mem_read_length*8) , endness = angr.archinfo.Endness.LE, disable_actions=True, inspect=False)
                            state.ch.chain_addr = state.ch.chain_addr + [state.inspect.mem_read_address]
                        if 'kl' in a:
                            state.memory.store(state.inspect.mem_read_address,claripy.BVS('kl', state.inspect.mem_read_length*8) , endness = angr.archinfo.Endness.LE, disable_actions=True, inspect=False)
                            state.ch.chain_addr = state.ch.chain_addr + [state.inspect.mem_read_address]
                        if 'kr' in a:
                            state.memory.store(state.inspect.mem_read_address,claripy.BVS('kr', state.inspect.mem_read_length*8) , endness = angr.archinfo.Endness.LE, disable_actions=True, inspect=False)
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
                        if state.solver.eval(state.inspect.mem_read_address - state.regs.rsp) > 1024 and (state.solver.eval(state.regs.rsp - state.inspect.mem_read_address ) > 1024):
                            state.memory.store(state.inspect.mem_read_address,claripy.BVS('kl', state.inspect.mem_read_length*8), endness = angr.archinfo.Endness.LE, disable_actions=True, inspect=False)              
                            state.ch.chain_addr = state.ch.chain_addr + [state.inspect.mem_read_address]


                def track_call(state):
                    global loop_func            
                    l = len(state.ch.chain_loop_func)//2
                    while l >= 1:
                        l = l-1
                        if state.solver.eval(state.inspect.function_address) == state.ch.chain_loop_func[2*l+1] and state.inspect.instruction == state.ch.chain_loop_func[2*l]:
                            j = 0
                            for i in range(0, len(loop_func)):
                                if loop_func[i] == state.solver.eval(state.inspect.function_address):
                                    j = 1
                                    break
                            if j == 0:
                                loop_func = loop_func + [state.solver.eval(state.inspect.function_address)]
                            break                   
                    state.ch.chain_loop_func = state.ch.chain_loop_func + [state.inspect.instruction]
                    state.ch.chain_loop_func = state.ch.chain_loop_func + [state.solver.eval(state.inspect.function_address)]

                
                initial_state.inspect.b('instruction', action=track_instr)
                initial_state.inspect.b('mem_write', when=angr.BP_BEFORE,action=track_write_mem_before)
                initial_state.inspect.b('mem_read', when=angr.BP_BEFORE, action=track_read_mem_before)

                if (fun_name in tainted_func) and (tainted_func[fun_name] & 1 == 1): 
                    initial_state.inspect.b('mem_read', when=angr.BP_BEFORE, action=track_read_mems)

                initial_state.inspect.b('call', when=angr.BP_BEFORE, action=track_call)

                simulation = project.factory.simgr(initial_state)
                simulation.use_technique(angr.exploration_techniques.oppologist.Oppologist())
                simulation.use_technique(angr.exploration_techniques.DFS())
                simulation.use_technique(angr.exploration_techniques.loop_seer.LoopSeer(cfg=None, functions=None, loops=None, use_header=False, bound=1, bound_reached=None, discard_stash='spinning', limit_concrete_loops=True))
                simulation.use_technique(angr.exploration_techniques.lengthlimiter.LengthLimiter(1000, drop=False))
                print(simulation.run(),file=f_exec_inf)


   
j = 0
z = 0
while (len(loop_func) - j) != 0:
    j = len(loop_func)
    for i in range(z, len(loop_func)):
        successors = cgv.successors(loop_func[i])
        for s in successors:
            if cfg.kb.functions[s].name[0:3] != 'Unr' and cfg.kb.functions[s].name[0:3] != 'sub' and cfg.kb.functions[s].name[0:1] != '_':
                if cfg.kb.functions[s].addr in loop_func:
                    loop_func = loop_func
                else:
                    loop_func = loop_func +  [cfg.kb.functions[s].addr] 
    z = j   

print("++++++++++++++++++++++++++++", file=f_exec_inf)


loop_func_trac = []
for i in range(0, len(loop_func)):   
    for func in cfg.kb.functions:
        if cfg.kb.functions[func].addr == loop_func[i] and cfg.kb.functions[func].name in traced_func:
            loop_func_trac = loop_func_trac + [cfg.kb.functions[func].addr]
            loop_func_trac = loop_func_trac + [cfg.kb.functions[func].name]
            break



for i in range(0, len(loop_func_trac)//2):
      
    for x in range(0, k):

        if loop_func_trac[2*i] == call_chain[x][0] and x != 47 and x != 49 and x != 260:

            start_address = call_chain[x][0]
            fun_name = call_chain[x][1]
            lop = 0
       

            if ((fun_name in tainted_func) and (tainted_func[fun_name] & 252 != 0)):

                print(x,file=f_exec_inf)
                print(fun_name, file=f_exec_inf)
                print("{:x}".format(start_address),file=f_exec_inf)
                project = angr.Project("/.../evaluation/wolfssl_rsa_o2/symbolic_exec/wolfssl", auto_load_libs=False)
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
                        project.hook_symbol(call_chain[x][2*d + 1], Hook_Untaint())    
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
                            state.memory.store(state.inspect.mem_read_address,claripy.BVS('h', state.inspect.mem_read_length*8) , endness = angr.archinfo.Endness.LE, disable_actions=True, inspect=False)
                            state.ch.chain_addr = state.ch.chain_addr + [state.inspect.mem_read_address]

               
                initial_state.inspect.b('instruction', action=track_instr)
                initial_state.inspect.b('mem_write', when=angr.BP_BEFORE,action=track_write_mem_before)
                initial_state.inspect.b('mem_read', when=angr.BP_BEFORE, action=track_read_mem_before)

                # if (fun_name in resu) and (resu[fun_name] & 1 == 1): 
                #     initial_state.inspect.b('mem_read', when=angr.BP_BEFORE, action=track_read_mems)
                    

                simulation = project.factory.simgr(initial_state)
                simulation.use_technique(angr.exploration_techniques.oppologist.Oppologist())
                simulation.use_technique(angr.exploration_techniques.DFS())
                simulation.use_technique(angr.exploration_techniques.loop_seer.LoopSeer(cfg=None, functions=None, loops=None, use_header=False, bound=1, bound_reached=None, discard_stash='spinning', limit_concrete_loops=True))
                simulation.use_technique(angr.exploration_techniques.lengthlimiter.LengthLimiter(1000, drop=False))
                print(simulation.run(),file=f_exec_inf)
            break
                












