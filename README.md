# Manual interaction

Immediately after CGC, we played in the DEFCON CTF finals, aided by mechaphish!
We quickly realized that the CRS was going to do very little without human assistance, so we wrote this script during the CTF to interact with the mechaphish database.

## What's inside?

```bash
andrew@delta:/home/angr/cgc/manual-interaction$ python crs.py -h
usage: crs.py [-h]
           {patch,exploit,insert-test,insert-crash,insert,create-cs,dr-proctor,download-exploits}
           ...

positional arguments:
  {patch,exploit,insert-test,insert-crash,insert,create-cs,dr-proctor,download-exploits}
                        sub-commands
    patch               do stuff with patches
    exploit             upload a exploit
    insert-test         insert a test for AFL
    insert-crash        insert a crash for AFL
    insert              insert a test or crash for AFL/Rex
    create-cs           upload a challenge set
    dr-proctor          poke around the binaries, then send the exam results
                        to the CRS
    download-exploits   download all a CS's exploits

optional arguments:
  -h, --help            show this help message and exit


andrew@delta:/home/angr/cgc/manual-interaction$ python crs.py patch -h
usage: crs.py patch [-h] {upload,list,field,download} ...

positional arguments:
  {upload,list,field,download}
                        sub-commands
    upload              upload a patch
    list                list the patches available for currently fielded CSes
    field               field a patch
    download            download CBNs for a CS

optional arguments:
  -h, --help            show this help message and exit


andrew@delta:/home/angr/cgc/manual-interaction$ python crs.py exploit -h
usage: crs.py exploit [-h] [--type {type1,type2}]
                   [--method {unclassified,exploration,circumstantial,shellcode,rop,fuzzer,backdoor}]
                   [--reliability RELIABILITY] [--source SOURCE]
                   cs exploit

positional arguments:
  cs                    the challenge set name
  exploit               compiled exploit to upload

optional arguments:
  -h, --help            show this help message and exit
  --type {type1,type2}  type of exploit
  --method {unclassified,exploration,circumstantial,shellcode,rop,fuzzer,backdoor}
                        what kind of exploit this is
  --reliability RELIABILITY
                        the reliability of the exploit
  --source SOURCE       source code of exploit


andrew@delta:/home/angr/cgc/manual-interaction$ python crs.py insert-test -h
usage: crs.py insert-test [-h] cs test

positional arguments:
  cs          the challenge set name
  test        test to upload

optional arguments:
  -h, --help  show this help message and exit


andrew@delta:/home/angr/cgc/manual-interaction$ python crs.py insert-crash -h
usage: crs.py insert-crash [-h]
                        cs crash
                        {unclassified,unknown,ip_overwrite,partial_ip_overwrite,uncontrolled_ip_overwrite,bp_overwrite,partial_bp_overwrite,write_what_where,write_x_where,uncontrolled_write,arbitrary_read,null_dereference,arbitrary_transmit,arbitrary_receive}

positional arguments:
  cs                    the challenge set name
  crash                 crash to upload
  {unclassified,unknown,ip_overwrite,partial_ip_overwrite,uncontrolled_ip_overwrite,bp_overwrite,partial_bp_overwrite,write_what_where,write_x_where,uncontrolled_write,arbitrary_read,null_dereference,arbitrary_transmit,arbitrary_receive}
                        kind of crash (default 'ip_overwrite')

optional arguments:
  -h, --help            show this help message and exit


andrew@delta:/home/angr/cgc/manual-interaction$ python crs.py insert -h
usage: crs.py insert [-h] cs cb test

positional arguments:
  cs          the challenge set name
  cb          path to CB
  test        test/crash to upload

optional arguments:
  -h, --help  show this help message and exit


andrew@delta:/home/angr/cgc/manual-interaction$ python crs.py create-cs -h
usage: crs.py create-cs [-h] name

positional arguments:
  name        the name of the challenge set (what DARPA calls the CSID)

optional arguments:
  -h, --help  show this help message and exit


andrew@delta:/home/angr/cgc/manual-interaction$ python crs.py dr-proctor -h
usage: crs.py dr-proctor [-h] [-b] cs cb

positional arguments:
  cs           the name of the challenge set (what DARPA calls the CSID)
  cb           path to CB

optional arguments:
  -h, --help   show this help message and exit
  -b, --batch  batch mode


andrew@delta:/home/angr/cgc/manual-interaction$ python crs.py download-exploits -h
usage: crs.py download-exploits [-h] cs

positional arguments:
  cs          the name of the challenge set (what DARPA calls the CSID)

optional arguments:
  -h, --help  show this help message and exit
```

## Dr. Proctor

The doctor is in.

This is a tool that basically launches a challenge set, lets you interact with it, and sends the interaction to the database as a test case.
This was incredibly useful during the CTF!

It is worth noting that this requires the challenge set name to be an integer.
