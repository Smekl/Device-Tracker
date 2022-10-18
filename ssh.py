
import os
import fcntl
import array
import termios
import subprocess


class SSHClient(object):

    def __init__(self, ip, username, keyfile):
        self.ip = ip
        self.username = username
        self.keyfile = keyfile

    def exec_command(self, cmd):
        proc = subprocess.Popen(f'ssh -o "StrictHostKeyChecking no" -n -i {self.keyfile} {self.username}@{self.ip} {cmd}', shell=True, stdout=subprocess.PIPE)
        return SSHCommand(self, proc, cmd)


class SSHCommand(object):

    def __init__(self, client, proc, cmd,):
        self.client = client
        self.proc = proc
        self.cmd = cmd
        self.__set_nonblock()

    def __set_nonblock(self):
        fcntl.fcntl(self.proc.stdout.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)

    def readline(self):
        return self.proc.stdout.readline().decode()

    def size(self):
        return len(self.proc.stdout.peek())

    def close(self):
        self.proc.kill()
        return self.proc.wait()

    def fileno(self):
        return self.proc.stdout.fileno()

    def flush(self):
        self.proc.stdout.read()