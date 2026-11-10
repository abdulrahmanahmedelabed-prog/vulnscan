import os
import shlex


def run_backup(name):
    os.system("tar czf backup.tgz " + name)


def run_backup_safely(name):
    os.system("tar czf backup.tgz -- " + shlex.quote(name))
