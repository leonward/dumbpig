dumbpig
=======
An automated way to check for "dumb" snort rules.

Requirements
------------
Perl, LWP::Simple, and Parse::Snort.

Setup
-------
On CentOS 6/7, setup is as follows:

```
sudo yum install perl-CPAN perl-libwww-perl perl-Class-Accessor
sudo cpan -i "Parse::Snort"
```

On Mac OS with Perlbrew:
Note, don't mess with your system Perl on OSX, it will bite you. Perlbrew is your friend.

```
$ cpanm Parse::Snort
$ ./dumbpig.pl
```

Usage
-----
```
$ perl dumbpig.pl

DumbPig version 0.3 - leon@leonward.com
      __,,    ( Dumb-pig says     )
    ~(  oo ---( "ur rulz r not so )
      ''''    ( gud akshuly" *    )

DumbPig Configuration
*********************************************
* Sensitivity level - 4/4
* Processing File - 0
* Quiet mode : Disabled
*********************************************
Error : Please specify a rules file
Usage dumbPig <args>
        -r or --rulefile    <rulefile>
        -s or --sensitivity <1-4> Sensitivity level, Higher the number, the higher the pass-grade
        -b or --blacklist   Enable blacklist output (see Marty's Blog post for details)
        -p or --pause   Pause for ENTER after each FAIL
        -w or --write   Filename to wite CLEAN rules to
        -q or --quiet   Suppress FAIL, only provide summary
        -d or --disabled    Check rules that are disabled i.e commented out #alert # alert etc
        -v or --verbose Verbose output for debugging
        -c or --censor  Censor rules in the output, in case you dont trust everyone
        -f or --forcefail   Force good rules to FAIL. Allows output of all rules
```

Output
------
The output of dumbpig against a file with bad rules:

```
$ perl dumbpig.pl -r bad.rules

DumbPig version 0.2 - leon.ward@sourcefire.com
      __,,    ( Dumb-pig says     )
        ~(  oo ---( "ur rulz r not so )
      ''''    ( gud akshuly" *    )

DumbPig Configuration
*********************************************
* Sensitivity level - 4/4
* Processing File - bad.rules
* Quiet mode : Disabled
*********************************************
Issue 1
2 Problem(s) found with rule on line 5 of bad.rules

alert ip any any -> any 53  ( \
    msg:"DNS lookup for foo.com using IP proto with port numbers"; \
    content:"baddomain"; \
    sid:1; \
    rev:1; \
)
- IP rule with port number (or var that could be set to a port number). This is BAD and invalid syntax.
  It is likely that this rule head is not functioning as you expect it to.
  The IP protocol doesn't have port numbers.
  If you want to inspect both UDP and TCP traffic on specific ports use two rules, its faster and valid syntax.
- No classification specified - Please add a classtype to add correct priority rating

Rule source sid: 1
alert ip any any -> any 53 (msg: "DNS lookup for foo.com using IP proto with port numbers"; content:"baddomain"; sid:1; rev:1)
=============================================================================
Issue 2
2 Problem(s) found with rule on line 6 of bad.rules

alert tcp any any -> any 80  ( \
    msg:"fastpattern not"; \
    content:"short1"; \
    content:"short2"; \
    content:"looooooong"; \
    http_uri; \
    sid:2; \
    rev:1; \
)
- No classification specified - Please add a classtype to add correct priority rating
- TCP, without flow. Consider adding flow to provide better state tracking on this TCP based rule

Rule source sid: 2
alert tcp any any -> any 80 (msg: "fastpattern not"; content:"short1"; content: "short2"; content: "looooooong"; http_uri; sid:2; rev:1)
=============================================================================
Issue 3
<snip>
=============================================================================
--------------------------------------
Total: 4 fails over 4 rules (8 lines) in bad.rules
- Contact leon.ward@sourcefire.com
```

License
-------
GNU General Public License (GPL) v2