## Verify
Verify digitally signed ZIP archives.

This project is a reincarnation of [https://github.com/Axeos/verify_jar](https://github.com/Axeos/verify_jar) inspired by __jarsigner__.

## Requirements
- JRE 1.8+

No additional dependencies used.

## Usage
Download the latest version from the [Releases](https://github.com/noleakseu/verify/releases/).
```shell
$ java -jar verify.jar
Signed ZIP verifier 1.0.1
Usage:
  java -jar verify.jar <options> <file>
Options:
  -date <yyyy-MM-dd> - check signature validity at given timestamp
  -verbose           - show verification steps
```

### Possible output
| Exit code | Message          |
|-----------|------------------|
| 0         | valid            |
| 1         | unsigned entries |
| 2         | not trusted      |
| 3         | expired          |
| 4         | not signed       |
| 5         | invalid          |
| 6         | error            |

