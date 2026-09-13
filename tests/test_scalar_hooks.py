"""Integration test against an owned fixture; requires Windows and pywin32."""
import argparse,hashlib,json,queue,subprocess,threading,time
from pathlib import Path
import win32file,win32pipe

parser=argparse.ArgumentParser()
parser.add_argument('--probe',required=True,type=Path)
parser.add_argument('--dll',required=True,type=Path)
parser.add_argument('--injector',type=Path,default=Path(__file__).resolve().parents[1]/'injector/mcp_inject.exe')
parser.add_argument('--output',required=True,type=Path)
args=parser.parse_args()
assert not args.output.exists(),'Preserve previous test evidence'
report={'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [args.probe,args.dll,args.injector]},'cases':[]}
process=subprocess.Popen([str(args.probe)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
lines=queue.Queue()
def read_lines():
    for line in process.stdout:lines.put(line.strip())
    lines.put('<EOF>')
threading.Thread(target=read_lines,daemon=True).start()
pipe=None
try:
    fields=lines.get(timeout=5).split();assert fields[0]=='ready' and int(fields[1])==process.pid
    addresses=fields[2:];assert len(addresses)==17
    injection=subprocess.run([str(args.injector),'--pid',str(process.pid),'--dll',str(args.dll)],capture_output=True,text=True,timeout=20)
    assert injection.returncode==0,injection.stdout+injection.stderr
    for attempt in range(30):
        try:
            pipe=win32file.CreateFile(rf'\\.\pipe\mcp_dbg_{process.pid}',win32file.GENERIC_READ|win32file.GENERIC_WRITE,0,None,win32file.OPEN_EXISTING,0,None);break
        except OSError:time.sleep(.1)
    assert pipe is not None
    win32pipe.SetNamedPipeHandleState(pipe,win32pipe.PIPE_READMODE_MESSAGE,None,None)
    def send(command):
        win32file.WriteFile(pipe,command.encode());_,data=win32file.ReadFile(pipe,131072)
        return json.loads(data.decode())
    def call(count):
        process.stdin.write(str(count)+'\n');process.stdin.flush()
        return lines.get(timeout=5)
    for count,address in enumerate(addresses):
        expected=f'{4321+sum(i*i for i in range(1,count+1))} 8765'
        baseline=call(count);assert baseline==expected,(count,baseline,expected)
        installed=send(f'HOOK_TYPED {address} {count} test_{count}');assert installed['status']=='ok',installed
        observed=call(count);assert observed==expected,(count,observed,expected)
        log=send(f'HOOK_LOG {address} 1');assert log['status']=='ok',log
        assert send(f'UNHOOK {address}')['status']=='ok'
        assert call(count)==expected
        report['cases'].append({'arity':count,'baseline':baseline,'hooked':observed,'log':log})
    for count in [-1,17]:assert send(f'HOOK_TYPED {addresses[0]} {count}')['status']=='error'
    process.stdin.write('-1\n');process.stdin.flush();assert process.wait(timeout=5)==0
    report['passed']=17
finally:
    if pipe is not None:win32file.CloseHandle(pipe)
    if process.poll() is None:process.terminate();process.wait(timeout=5)
    args.output.write_text(json.dumps(report,indent=2)+'\n')
print('PASS: 17 scalar arities; stack arguments, entry/return LastError and unhook restoration')
