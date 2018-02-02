Testing Guidelines
==================

* All changes shall be accompanied by a test
* All tests adhere to pep8 standards
* All tests must be stand-alone and deterministic
* All tests covering remote transactions will have a fixture file
    * fixture file names shall match method names
    * fixtures should be edited to include no *more* data than necessary
    * fixtures shall not include accessible IP addresses or credentials
* All changes shall be associated with an issue number
