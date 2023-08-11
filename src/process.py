#!/usr/bin/python3
# -*- coding: utf-8 -*-

f = open('/.../taint.txt', 'r')                  
trace_func = {}
tainted_func = {}
for line in f.readlines():
    line = line.strip()
    if not len(line):
        continue
    if ":" in line:
        if len(line.split(':')[1]) > 3 and len(line.split(':')[1]) < 12:
            if line.split(':')[0] in trace_func:
                trace_func[line.split(':')[0]] = trace_func[line.split(':')[0]]|int(line.split(':')[1], 2)
            else:
                trace_func[line.split(':')[0]] = int(line.split(':')[1], 2)
for k in trace_func:
    if trace_func[k] != 0:
        tainted_func[k] = trace_func[k]
f.close()

print(tainted_func)
print(len(tainted_func))
print(trace_func)
print(len(trace_func))

f1 = open('/.../tainted_func.txt', 'w')

for k,v in tainted_func.items():
	f1.write(str(k)+':'+str(v)+'\n')
	
f1.close()


f2 = open('/.../traced_func.txt', 'w')

for k,v in trace_func.items():
	f2.write(str(k)+':'+str(v)+'\n')
	
f2.close()

          
