.. image:: https://img.shields.io/pypi/v/ixnetwork.svg
    :target: https://pypi.org/project/ixnetwork

.. image:: https://img.shields.io/pypi/pyversions/ixnetwork.svg
    :target: https://pypi.org/project/ixnetwork

.. image:: https://img.shields.io/badge/license-MIT-green.svg
    :target: https://en.wikipedia.org/wiki/MIT_License




IxNetwork is the Python package for the IxNetwork Low Level API that allows you to configure and run IxNetwork tests.

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

* yum install python-tox
* tox

Documentation
=============
| For general language documentation of IxNetwork API see the `Low Level API Guide <http://downloads.ixiacom.com/library/user_guides/ixnetwork/9.00/EA_9.00_Rev_A/QuickReferenceGuides/LLAPI_reference_guide.pdf>`_ and the `IxNetwork API Help <http://downloads.ixiacom.com/library/user_guides/ixnetwork/9.00/EA_9.00_Rev_A/IxNetwork_HTML5/IxNetwork.htm>`_.
| This will require a login to `Ixia Support <https://support.ixiacom.com/user-guide>`_ web page.



IxNetwork API server / Python Support
=====================================
IxNetwork.py lib 9.00.1915.16 supports:

* Python 2.7, 3.3, 3.4, 3.5, 3.6, 3.7
* IxNetwork Windows API server 8.40+
* IxNetwork Web Edition (Linux API Server) 8.50+

Compatibility with older versions may continue to work but it is not actively supported.

Compatibility Policy
====================
IxNetwork Low Level API library is supported on the following operating systems:

* Microsoft Windows
* CentOS 7 on x64 platform

Related Projects
================
* IxNetwork API Tcl Bindings: https://github.com/ixiacom/ixnetwork-api-tcl
* IxNetwork API Perl Bindings: https://github.com/ixiacom/ixnetwork-api-pl
* IxNetwork API Ruby Bindings: https://github.com/ixiacom/ixnetwork-api-rb
