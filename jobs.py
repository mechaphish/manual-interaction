#!/usr/bin/env python

import os
import sys

base_dir = os.path.realpath(os.path.dirname(__file__))
worker_dir = os.path.join(base_dir, 'workers')

if not os.path.exists(worker_dir):
    os.mkdir(worker_dir)

from dotenv import load_dotenv
load_dotenv(os.path.join(base_dir, '.env'))

from farnsworth.models import Job

def color_me(s, padto=0, ljust=True, extra=None):
    if len(s) < padto:
        if ljust:
            s = s.ljust(padto)
        else:
            s = s.rjust(padto)

    hcolor = sum(map(ord, s)) % 7 + 31
    return '\x1b[%d%sm%s\x1b[0m' % (hcolor, ';' + str(extra) if extra is not None else '', s)

def spawn_job(ident):
    os.chdir(worker_dir)
    logfile = ident + '.log'
    pidfile = ident + '.pid'
    os.system('JOB_ID=%s worker >%s 2>&1 & echo $! >%s' % (ident, logfile, pidfile))

def is_job_alive(jid):
    pid_file = os.path.join(worker_dir, '%d.pid' % jid)
    try:
        with open(pid_file) as f: the_pid = int(f.read())
        os.kill(the_pid, 0)
    except (OSError, IOError):
        return False
    return True

def print_jobs():
    print '  ID   Priority   CS Name           CB Name                 Worker            Status'
    print '--------------------------------------------------------------------------------------'
    for j in Job.select(Job.id, Job.worker, Job.priority, Job.cs, Job.cbn, Job.started_at) \
                .where(Job.completed_at == None) \
                .order_by(Job.priority.desc()).execute():

        cs = '' if j.cs is None else j.cs.name
        cbn = '' if j.cbn is None else j.cbn.name

        if j.started_at is None:
            status = 'pending'
        elif is_job_alive(j.id):
            status = 'alive'
        else:
            status = 'crashed!'

        print ' %6d    %3d   %s   %s   %s   %s' % (j.id, j.priority, color_me(cs, 15), color_me(cbn, 20), color_me(j.worker, 20), color_me(status))

def usage():
    print 'Usage: ./jobs.py (list | start <id>)'

if __name__ == '__main__':
    try:
        if sys.argv[1] == 'list':
            print_jobs()
        elif sys.argv[1] == 'start':
            spawn_job(sys.argv[2])
        else:
            usage()
    except KeyError:
        usage()
