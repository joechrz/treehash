# treehash 

calculates the sha256 tree-hash according to the algorithm laid out at
http://docs.aws.amazon.com/amazonglacier/latest/dev/checksum-calculations.html

if no filename is specified, reads from stdin

```
Usage: treehash [options] [<filename>]
       treehash --help

Options:
  -b, --binary      Output the result in binary form (default: hex string)
```

