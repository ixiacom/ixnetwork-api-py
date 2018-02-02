.. image:: https://img.shields.io/pypi/v/ixnetwork.svg
    :target: https://pypi.org/project/ixnetwork

.. image:: https://img.shields.io/pypi/pyversions/ixnetwork.svg
    :target: https://pypi.org/project/ixnetwork

.. image:: https://img.shields.io/badge/license-MIT-green.svg
    :target: https://en.wikipedia.org/wiki/MIT_License




IxNetwork.py is the Python library for the IxNetwork Low Level API that allows you to configure and run IxNetwork tests.

Installing
==========

| The master branch always contains the latest official release. It is only updated on new IxNetwork releases. Official releases are posted to `PyPI <https://pypi.python.org/pypi/ixnetwork/>`_. 
| The dev branch contains improvements and fixes of the current release that will go into the next release version.

* To install the official release just run
  ``pip install --upgrade ixnetwork``.
* To install the version in `github <https://github.com/ixiacom/ixnetwork-api-py>`_ use
  ``python setup.py develop`` for development install or
  ``python setup.py install``.

Testing
=======
| Unit tests can be invoked by running ``python setup.py test`` command.
| We strongly recommend that you test the package installation and unit test execution against the python environments listed in ''tox.ini''.
| For this you can use `tox <https://testrun.org/tox/>`_ utility. Run the following:

* apt-get install python-tox
* tox

Documentation
=============
| For general language documentation of IxNetwork API see `IxNetwork API Docs <http://downloads.ixiacom.com/library/user_guides/IxNetwork/8.31/EA_8.31_Rev_A/LowLevelApiGuide.zip>`_.
| This will require a login to `Ixia Support <https://support.ixiacom.com/user-guide>`_ web page.


IxNetwork API server / Python Support
=====================================
IxNetwork.py lib 8.40.1124.8 supports IxNetwork Windows API server 8.40+ and Python 2.7, 3.3, 3.4, 3.5 and 3.6.

Compatibility Policy
====================
| IxNetwork.py supported IxNetwork API server version and Python versions are mentioned in the above "Support" section.
| Compatibility with older versions may work but will not be actively supported.

Related Projects
================
* IxNetwork API Tcl Bindings: https://github.com/ixiacom/ixnetwork-api-tcl
* IxNetwork API Perl Bindings: https://github.com/ixiacom/ixnetwork-api-pl
* IxNetwork API Ruby Bindings: https://github.com/ixiacom/ixnetwork-api-rb
