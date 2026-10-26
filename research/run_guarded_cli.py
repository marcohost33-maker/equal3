"""POSIX-only subprocess guard for local Equal3 CLI experiments.

Limits are *per child process*, not a complete isolation boundary or sandbox.
Trusted paths and input sources only. No shell invocation.
"""
import argparse, os, subprocess, sys

def main(argv=None):
    p=argparse.ArgumentParser(description='Equal3 local CLI with OS resource limits (POSIX)')
    p.add_argument('--memory-mib',type=int,default=768)
    p.add_argument('--cpu-seconds',type=int,default=15)
    p.add_argument('--wall-seconds',type=int,default=20)
    p.add_argument('--file-mib',type=int,default=128)
    p.add_argument('command',nargs=argparse.REMAINDER,help='CLI args after --, e.g. status db --key-file key')
    a=p.parse_args(argv)
    if os.name!='posix':p.error('POSIX only')
    if not (128<=a.memory_mib<=65536 and 1<=a.cpu_seconds<=3600 and 1<=a.wall_seconds<=3600 and 1<=a.file_mib<=2048):
        p.error('resource limits outside accepted range')
    args=a.command[1:] if a.command and a.command[0]=='--' else a.command
    if not args:p.error('Equal3 CLI command required')
    import resource
    def setup():
        resource.setrlimit(resource.RLIMIT_AS,(a.memory_mib*1048576,a.memory_mib*1048576))
        resource.setrlimit(resource.RLIMIT_CPU,(a.cpu_seconds,a.cpu_seconds))
        resource.setrlimit(resource.RLIMIT_FSIZE,(a.file_mib*1048576,a.file_mib*1048576))
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    cli=os.path.join(os.path.dirname(__file__),'store_cli.py')
    try:
        done=subprocess.run([sys.executable,cli,*args],preexec_fn=setup,timeout=a.wall_seconds,check=False)
        return done.returncode
    except subprocess.TimeoutExpired:
        print('Equal3 CLI exceeded wall-clock budget',file=sys.stderr)
        return 124

if __name__=='__main__':raise SystemExit(main())
