#!/usr/bin/env python

import os
import argparse
import datetime
import subprocess
from select import select

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

# import logging
# logger = logging.getLogger('peewee')
# logger.setLevel(logging.DEBUG)
# logger.addHandler(logging.StreamHandler())

import peewee
import farnsworth
import farnsworth.config
import farnsworth.models
from farnsworth.models import (
    ChallengeBinaryNode as CBN,
    ChallengeSetFielding as CSF,
    ChallengeSet as CS,
    PollFeedback as PF,
    PatchScore as PS,
    PatchType as PT,
    Round,
    Team,
    Exploit,
    Job,
    IDSRule,
    CSSubmissionCable,
    Crash,
    Test,
)
import shellphish_qemu
from rex import NonCrashingInput, QuickCrash

def create_cs(args):
    CS.create(name=args.name)

def create_patchtype(args):
    PT.create(name=args.name, exploitability=args.exploitability, functionality_risk=args.functionality_risk)

def create_round(args):
    if not len(args.challenge_sets):
        fielded = [ cs.name for cs in CS.fielded_in_round() ]
    else:
        fielded = args.challenge_sets
    new_round = Round.create(num=args.number if args.number is not None else Round.current_round()+1)

    for f in fielded:
        cs = CS.select().where(CS.name == f).get()
        CSF.create(cs=cs, team=Team.get_our(), available_round=new_round)

def upload_cbns(args):
    cs = CS.select().where(CS.name == args.cs)

    patch_type, _ = PT.get_or_create(name="manual", functionality_risk=1.0, exploitability=0.0)

    cbns = []
    for patched_file in args.patched_files:
        with open(patched_file) as f:
            content = f.read()
        try:
            cbn = CBN.create(cs=cs, blob=content, name=patched_file, patch_type=patch_type)
        except peewee.IntegrityError:
            print "CBN already exists. Fetching."
            cbn = CBN.select().where(CBN.name == args.patched_file, CBN.cs == cs, CBN.blob == content)
        cbns.append(cbn)

    if args.field:
        ids = IDSRule.get_or_create(cs=target_cs, rules='')
        CSSubmissionCable.get_or_create(cs=target_cs, cbns=cbns, ids=ids, round=Round.current_round())

    if args.eF is not None and args.eT is not None and args.eM is not None and cbn.patch_type is not None:
        perf_score = {
            'score': {
                'ref': { 'task_clock': 1.0, 'rss': 1.0, 'flt': 1.0, 'file_size': 1.0 },
                'rep': {
                    'task_clock': args.eT, 'file_size': args.size_overhead,
                    'rss': args.eM, 'flt': args.eM,
                }
            }
        }
        PS.create(
            cs=cs, perf_score=perf_score, patch_type=cbn.patch_type,
            has_failed_polls=args.eF != 0, failed_polls=args.eF
        )
    if args.pT is not None and args.pM is not None and args.pS is not None:
        csf.poll_feedback = PF.create(
            cs=cs,
            round_id=Round.current_round().id,
            success = args.pS,
            time_overhead=args.pT,
            memory_overhead=args.pM,
            size_overhead=args.size_overhead
        )
        csf.save()

def format_patch(p):
    return "{} ({}): {} bytes, type {}".format(p.name, p.sha256, p.size, p.patch_type.name if p.patch_type is not None else None)

def list_patches(args):
    wanted_fields = (CBN.name, CBN.size, CBN.sha256, CBN.patch_type, CBN.is_blacklisted)
    q = CBN.select(*wanted_fields)

    if args.cs is not None:
        cs = CS.select().where(CS.name == args.cs)
        for patch in q.where(CBN.cs == cs):
            print format_patch(patch)
    else:
        for cs in CS.fielded_in_round():
            print "CS {}:".format(cs.name)
            for patch in q.where(CBN.cs == cs):
                print format_patch(patch)
            print ""

def field_cbns(args):
    cs = CS.select().where(CS.name == args.cs)
    # i know i could use one query for this, but then we might get duplicate CBNs and more than we want
    cbns = [CBN.get(CBN.cs == cs, CBN.sha256 == sha) for sha in args.patched_shas]
    ids, _ = IDSRule.get_or_create(cs=cs, rules='')
    CSSubmissionCable.get_or_create(cs=cs, cbns=cbns, ids=ids, round=Round.current_round())

def quiet_mkdir(p):
    try:
        os.mkdir(p)
    except OSError:
        pass

def download_cbns(args):
    cs = CS.get(CS.name == args.cs)
    dir_name = 'binaries-cs-%s' % cs.name
    quiet_mkdir(dir_name)

    first = True
    shas = set()
    tm = CSF.cbns.get_through_model()
    for fielding in (CSF
                     .select(CSF, Team, Round, tm)
                     .join(Team)
                     .switch(CSF)
                     .join(Round,
                           on=(Round.id == CSF.available_round))
                     .switch(CSF)
                     .join(tm)
                     .join(CBN)
                     .where(CSF.cs == cs)
                     .order_by(Round.created_at)):
        if first:
            name = "original"
            first = False
        else:
            name = "team-%s" % fielding.team.name

        quiet_mkdir(os.path.join(dir_name, name))

        print "before loop..."
        for cbn in fielding.cbns:
            print "in loop"
            if cbn.sha256 in shas:
                print "already saw this one!"
                continue

            with open(os.path.join(dir_name, name, name + "_round-%s-" % fielding.available_round.num + cbn.name.replace('/', '_')), 'wb') as f:
                f.write(cbn.blob)
            shas.add(cbn.sha256)

    our_patches = os.path.join(dir_name, 'our-patches')
    quiet_mkdir(our_patches)
    for cbn in CBN.select().where(CBN.cs == cs, ~(CBN.sha256.in_(shas))):
        with open(os.path.join(our_patches, cbn.name.replace('/', '_') + "-" + cbn.sha256), 'wb') as f:
            f.write(cbn.blob)

def fieldings(args):
    for cs in CSF.select().join(CS.fielded_in_round(round_=args.round)).where(CSF.submission_round):
        pass

def ensure_teams(args): #pylint:disable=unused-argument
    try:
        Team.get_our()
    except Team.DoesNotExist: #pylint:disable=no-member
        Team.create(name=Team.OUR_NAME)

def upload_exploit(args):
    cs = CS.select().where(CS.name == args.cs)
    exploit = args.exploit.read()
    source = args.source.read() if args.source is not None else None

    # first we have to make a fake job
    job = Job.create(cs=cs, completed_at=datetime.datetime.now(), worker="garbage")

    # now actually add the exploit
    Exploit.create(cs=cs, job=job, blob=exploit, pov_type=args.type, method=args.method, reliability=args.reliability, c_code=source)

def insert_test(args):
    cs = CS.select().where(CS.name == args.cs)
    test = args.test.read()

    # first we have to make a fake job
    job = Job.create(cs=cs, completed_at=datetime.datetime.now(), worker="garbage")

    Test.create(cs=cs, job=job, blob=test)

def insert_crash(args):
    cs = CS.select().where(CS.name == args.cs)
    test = args.crash.read()
    kind = args.crash_kind

    # first we have to make a fake job
    job = Job.create(cs=cs, completed_at=datetime.datetime.now(), worker="garbage")

    Crash.create(cs=cs, kind=kind, job=job, blob=test)

def insert(args):
    test = args.test.read()
    try:
        qc = QuickCrash(args.cb, test)
        crash = True
    except NonCrashingInput:
        crash = False

    cs = CS.get(name=args.cs)
    job = Job.create(cs=cs, completed_at=datetime.datetime.now(), worker="garbage")

    if crash:
        Crash.create(cs=cs, kind=qc.kind, job=job, blob=test)
        print "inserted crash of type %s!" % qc.kind
    else:
        Test.create(cs=cs, job=job, blob=test)
        print "inserted test!"

def add_test_or_crash(args):
    p = subprocess.Popen([shellphish_qemu.qemu_path('cgc-base'), args.cb], stdin=subprocess.PIPE)
    p.poll()
    test = ""

    if args.batch:
        test = sys.stdin.read()
        p.communicate(test)
    else:
        try:
            while p.returncode is None:
                r, _, _ = select([sys.stdin], [], [], 0.05)
                if r is not None:
                    b = sys.stdin.read(1)
                    test += b
                    p.stdin.write(b)

                p.poll()
        except KeyboardInterrupt:
            p.returncode = 0
        except IOError:
            p.returncode = 1

    if p.returncode == 0:
        print "Finished test, inserting now..."
        cs = CS.select().where(CS.name == args.cs)

        # first we have to make a fake job
        job = Job.create(cs=cs, completed_at=datetime.datetime.now(), worker="garbage")

        Test.create(cs=cs, job=job, blob=test)
        print "Test inserted!"
    else:
        print "Found a crash, inserting now..."

        qc = QuickCrash(args.cb, test)
        print "appears to be of type " + qc.kind

        print "cs = " + args.cs
        cs = CS.select().where(CS.name == args.cs)

        # first we have to make a fake job
        job = Job.create(cs=cs, completed_at=datetime.datetime.now(), worker="garbage")

        Crash.create(cs=cs, job=job, blob=test, kind=qc.kind)
        print "Crash inserted!"

def download_exploits(args):
    cs = CS.get(name=args.cs)
    dir_name = "exploits-cs-%s" % cs.name
    quiet_mkdir(dir_name)

    for e in cs.exploits:
        with open(os.path.join(dir_name, "%d_%s_%s.pov"), 'wb') as f:
            f.write(e.blob)

def _normal_float(val):
    return 0.0 <= val <= 1.0

def main(argv):
    parser = argparse.ArgumentParser(prog='fry')
    subparsers = parser.add_subparsers(help="sub-commands")

    # create_parser = subparsers.add_parser('create-db', help="create the db")
    # create_parser.set_defaults(func=lambda x: farnsworth.create_tables())

    # create_parser = subparsers.add_parser('teams', help="create the teams")
    # create_parser.set_defaults(func=ensure_teams)

    patch_parser = subparsers.add_parser('patch', help="do stuff with patches")
    patch_subparser = patch_parser.add_subparsers(help="sub-commands")

    upload_patch_parser = patch_subparser.add_parser('upload', help="upload a patch")
    upload_patch_parser.add_argument("cs", type=str, help="the challenge set name")
    upload_patch_parser.add_argument("patched_files", type=str, nargs='+', help="the patched files (you have to include ALL CBs for the service)")
    upload_patch_parser.add_argument("--ids-rule", type=str, help="a file containing the IDS rule")
    upload_patch_parser.add_argument("--eT", type=float, help="the estimated time overhead [0,1]")
    upload_patch_parser.add_argument("--eM", type=float, help="the estimated memory overhead [0,1]")
    upload_patch_parser.add_argument("--eF", type=int, help="the estimated number of failed polls")
    upload_patch_parser.add_argument("--pT", type=float, help="the exact (poll) memory overhead [0,1]")
    upload_patch_parser.add_argument("--pM", type=float, help="the exact (poll) memory overhead [0,1]")
    upload_patch_parser.add_argument("--pS", type=float, help="the exact (poll) success rate [0,1]")
    upload_patch_parser.add_argument("--size-overhead", type=float, help="the size overhead over the original binary")
    upload_patch_parser.add_argument("--field", type=bool, help="whether to immediately set this cbn to fielded", default=False)
    upload_patch_parser.set_defaults(func=upload_cbns)

    list_patches_parser = patch_subparser.add_parser('list', help="list the patches available for currently fielded CSes")
    list_patches_parser.add_argument("--cs", type=str, help="a specific challenge set")
    list_patches_parser.set_defaults(func=list_patches)

    field_patch_parser = patch_subparser.add_parser('field', help="field a patch")
    field_patch_parser.add_argument("cs", type=str, help="the challenge set name")
    field_patch_parser.add_argument("patched_shas", type=str, nargs='+', help="the shas of the patched binaries")
    field_patch_parser.set_defaults(func=field_cbns)

    download_patch_parser = patch_subparser.add_parser('download', help="download CBNs for a CS")
    download_patch_parser.add_argument("cs", type=str, help="the challenge set name")
    download_patch_parser.set_defaults(func=download_cbns)

    exploit_parser = subparsers.add_parser('exploit', help="upload a exploit")
    exploit_parser.add_argument("cs", type=str, help="the challenge set name")
    exploit_parser.add_argument("exploit", type=argparse.FileType("rb"), help="compiled exploit to upload")
    exploit_parser.add_argument("--type", type=str, choices=Exploit.pov_type.choices, help="type of exploit", default=Exploit.pov_type.choices[0])
    exploit_parser.add_argument("--method", type=str, choices=Exploit.method.choices, help="what kind of exploit this is", default=Exploit.method.choices[0])
    exploit_parser.add_argument("--reliability", type=_normal_float, help="the reliability of the exploit", default=1.0)
    exploit_parser.add_argument("--source", type=argparse.FileType("rb"), help="source code of exploit")
    exploit_parser.set_defaults(func=upload_exploit)

    test_insert_parser = subparsers.add_parser('insert-test', help="insert a test for AFL")
    test_insert_parser.add_argument("cs", type=str, help="the challenge set name")
    test_insert_parser.add_argument("test", type=argparse.FileType("rb"), help="test to upload")
    test_insert_parser.set_defaults(func=insert_test)

    crash_insert_parser = subparsers.add_parser('insert-crash', help="insert a crash for AFL")
    crash_insert_parser.add_argument("cs", type=str, help="the challenge set name")
    crash_insert_parser.add_argument("crash", type=argparse.FileType("rb"), help="crash to upload")
<<<<<<< HEAD
    crash_insert_parser.add_argument("crash_type", type=str, help="type of crash", choices=Crash.kind.choices)
=======
    crash_insert_parser.add_argument("crash_kind", type=str, help="kind of crash (default 'ip_overwrite')", choices=Crash.kind.choices)
>>>>>>> fc03de6... When inserting crashes, must declare kind
    crash_insert_parser.set_defaults(func=insert_crash)

    insert_parser = subparsers.add_parser('insert', help="insert a test or crash for AFL/Rex")
    insert_parser.add_argument("cs", type=str, help="the challenge set name")
    insert_parser.add_argument('cb', type=str, help="path to CB")
    insert_parser.add_argument("test", type=argparse.FileType("rb"), help="test/crash to upload")
    insert_parser.set_defaults(func=insert)

    # patchtype_parser = subparsers.add_parser('create-patchtype', help="create a new patch type")
    # patchtype_parser.add_argument('name', type=str, help="the name of the patch type")
    # patchtype_parser.add_argument('functionality-risk', type=float, help="the risk to break the binary [0, 1]")
    # patchtype_parser.add_argument('exploitability', type=float, help="the risk of exploitability [0, 1]")
    # patchtype_parser.set_defaults(func=create_patchtype)

    cs_parser = subparsers.add_parser('create-cs', help="upload a challenge set")
    cs_parser.add_argument('name', type=str, help="the name of the challenge set (what DARPA calls the CSID)")
    cs_parser.set_defaults(func=create_cs)

    dr_parser = subparsers.add_parser('dr-proctor', help="poke around the binaries, then send the exam results to the CRS")
    dr_parser.add_argument('cs', type=str, help="the name of the challenge set (what DARPA calls the CSID)")
    dr_parser.add_argument('cb', type=str, help="path to CB")
    dr_parser.add_argument('-b', '--batch', action='store_true', help="batch mode")
    dr_parser.set_defaults(func=add_test_or_crash)

    dl_parser = subparsers.add_parser('download-exploits', help="download all a CS's exploits")
    dl_parser.add_argument('cs', type=str, help="the name of the challenge set (what DARPA calls the CSID)")
    dl_parser.set_defaults(func=download_exploits)

    # rounds_parser = subparsers.add_parser('round', help="tick rounds")
    # rounds_parser.add_argument('--number', type=int, help="the new round number")
    # rounds_parser.add_argument('challenge_sets', nargs='*', help="the challenge set IDs to field this round")
    # rounds_parser.set_defaults(func=create_round)

    args = parser.parse_args(argv[1:])
    args.func(args)

if __name__ == '__main__':
    import sys
    main(sys.argv)
