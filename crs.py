#!/usr/bin/env python

import argparse
import datetime

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
)

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

def upload_cbn(args):
    cs = CS.select().where(CS.name == args.cs)
    with open(args.patched_file) as patched_file:
        content = patched_file.read()

    patch_type, _ = PT.get_or_create(name="manual", functionality_risk=1.0, exploitability=0.0)

    try:
        cbn = CBN.create(cs=cs, blob=content, name=args.patched_file, patch_type=patch_type)
    except peewee.IntegrityError:
        print "CBN already exists. Fetching."
        cbn = CBN.select().where(CBN.name == args.patched_file, CBN.cs == cs, CBN.blob == content)


    if args.field:
        csf = CSF.select().where(
            cs=cs, team=Team.get_our(), available_round=Round.current_round(), cbns=[cbn]
        )

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

def list_patches(args):
    for patch in CBN.select().join(CS.fielded_in_round()).where(CBN.patch_type.is_null(False)).group_by(CS.id):
        print patch

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

def _normal_float(val):
    return 0.0 <= val <= 1.0

def main(argv):
    parser = argparse.ArgumentParser(prog='fry')
    subparsers = parser.add_subparsers(help="sub-commands")

    # create_parser = subparsers.add_parser('create-db', help="create the db")
    # create_parser.set_defaults(func=lambda x: farnsworth.create_tables())

    # create_parser = subparsers.add_parser('teams', help="create the teams")
    # create_parser.set_defaults(func=ensure_teams)

    patch_parser = subparsers.add_parser('patch', help="upload a patch")
    patch_parser.add_argument("cs", type=str, help="the challenge set name")
    patch_parser.add_argument("patched_file", type=str, help="the patched file")
    patch_parser.add_argument("--ids-rule", type=str, help="a file containing the IDS rule")
    patch_parser.add_argument("--eT", type=float, help="the estimated time overhead [0,1]")
    patch_parser.add_argument("--eM", type=float, help="the estimated memory overhead [0,1]")
    patch_parser.add_argument("--eF", type=int, help="the estimated number of failed polls")
    patch_parser.add_argument("--pT", type=float, help="the exact (poll) memory overhead [0,1]")
    patch_parser.add_argument("--pM", type=float, help="the exact (poll) memory overhead [0,1]")
    patch_parser.add_argument("--pS", type=float, help="the exact (poll) success rate [0,1]")
    patch_parser.add_argument("--size-overhead", type=float, help="the size overhead over the original binary")
    patch_parser.add_argument("--field", type=bool, help="whether to immediately set this cbn to fielded", default=False)
    patch_parser.set_defaults(func=upload_cbn)

    exploit_parser = subparsers.add_parser('exploit', help="upload a exploit")
    exploit_parser.add_argument("cs", type=str, help="the challenge set name")
    exploit_parser.add_argument("exploit", type=argparse.FileType("rb"), help="compiled exploit to upload")
    exploit_parser.add_argument("--type", type=str, choices=Exploit.pov_type.choices, help="type of exploit", default=Exploit.pov_type.choices[0])
    exploit_parser.add_argument("--method", type=str, choices=Exploit.method.choices, help="what kind of exploit this is", default=Exploit.method.choices[0])
    exploit_parser.add_argument("--reliability", type=_normal_float, help="the reliability of the exploit", default=1.0)
    exploit_parser.add_argument("--source", type=argparse.FileType("rb"), help="source code of exploit")
    exploit_parser.set_defaults(func=upload_exploit)

    # patchtype_parser = subparsers.add_parser('create-patchtype', help="create a new patch type")
    # patchtype_parser.add_argument('name', type=str, help="the name of the patch type")
    # patchtype_parser.add_argument('functionality-risk', type=float, help="the risk to break the binary [0, 1]")
    # patchtype_parser.add_argument('exploitability', type=float, help="the risk of exploitability [0, 1]")
    # patchtype_parser.set_defaults(func=create_patchtype)

    cs_parser = subparsers.add_parser('create-cs', help="upload a challenge set")
    cs_parser.add_argument('name', type=str, help="the name of the challenge set (what DARPA calls the CSID)")
    cs_parser.set_defaults(func=create_cs)

    patches_parser = subparsers.add_parser('patches', help="list the patches available for currently fielded CSes")
    patches_parser.set_defaults(func=list_patches)

    # rounds_parser = subparsers.add_parser('round', help="tick rounds")
    # rounds_parser.add_argument('--number', type=int, help="the new round number")
    # rounds_parser.add_argument('challenge_sets', nargs='*', help="the challenge set IDs to field this round")
    # rounds_parser.set_defaults(func=create_round)

    args = parser.parse_args(argv[1:])
    args.func(args)

if __name__ == '__main__':
    import sys
    main(sys.argv)
