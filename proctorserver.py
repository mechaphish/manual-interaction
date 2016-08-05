#!/usr/bin/env python

import os
import datetime
import subprocess
from select import select
import SocketServer

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

import shellphish_qemu
from rex import QuickCrash
# fuck it
from farnsworth.models import *

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

class Handler(SocketServer.BaseRequestHandler):
    def handle(self):
        global cb, cs_name

        p = subprocess.Popen([shellphish_qemu.qemu_path('cgc-base'), cb], stdin=subprocess.PIPE, stdout=self.request.fileno(), stderr=self.request.fileno())
        p.poll()
        test = ""

        while p.returncode is None:
            r, _, _ = select([self.request], [], [], 0.05)
            if r:
                b = self.request.recv(1024)
                test += b
                p.stdin.write(b)

            print "polling"
            p.poll()

        if p.returncode == 0:
            self.request.sendall("Finished test, inserting now...\n")
            cs = ChallengeSet.select().where(ChallengeSet.name == cs_name)

            # first we have to make a fake job
            job = Job.create(cs=cs, completed_at=datetime.datetime.now(), worker="garbage")

            Test.create(cs=cs, job=job, blob=test)
            self.request.sendall("Test inserted!\n")
        else:
            self.request.sendall("Found a crash, inserting now...\n")

            qc = QuickCrash(cb, test)
            self.request.sendall("appears to be of type " + qc.kind + "\n")

            cs = ChallengeSet.select().where(ChallengeSet.name == cs_name)

            # first we have to make a fake job
            job = Job.create(cs=cs, completed_at=datetime.datetime.now(), worker="garbage")

            Crash.create(cs=cs, job=job, blob=test, kind=qc.kind)
            self.request.sendall("Crash inserted!\n")

import sys

cb = sys.argv[1]
cs_name = sys.argv[2]

host = "0.0.0.0"
port = 13370 + int(cs_name)

ThreadedTCPServer.allow_reuse_address = True
ThreadedTCPServer((host, port), Handler).serve_forever()
