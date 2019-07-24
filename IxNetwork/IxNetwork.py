#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 1997 - 2019 by IXIA Keysight
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


import sys
import socket
import select
from datetime import datetime

class IxNetError(Exception):
    '''Default IxNet error'''


from . import IxNetworkLegacy


class IxNet(object):
    """
    Set the IxNet object up
    """

    def __init__(self):
        self._version = '9.00.1915.16'
        self.OK = '::ixNet::OK'
        self.ERROR = '::ixNet::ERROR'
        self._transportType = None
        self.__ixNetworkSecure = None
        self._noApiKey = '00000000000000000000000000000000'
        self.__ixNetworkLegacy = IxNetworkLegacy.IxNet()
        self._debug = None

        try:
            from . import IxNetworkSecure
            self.__ixNetworkSecure = IxNetworkSecure.IxNet()
            self.__ixNetworkSecureImportError = None
        except (ImportError,):
            e = sys.exc_info()[1]
            self.__ixNetworkSecure = None
            self.__ixNetworkSecureImportError = e
            print("WARNING: {msg} ".format(msg=str(e)))
            print("If you are trying to connect to a Windows IxNetwork API Server on TCL port you can safely ignore this warning.")

    def _getCurrentTransport(self):
        if self.__ixNetworkSecure and self.__ixNetworkSecure._isConnected():
            return self.__ixNetworkSecure
        else:
            return self.__ixNetworkLegacy

    def _getSecureTransport(self):
        if self.__ixNetworkSecure:
            return self.__ixNetworkSecure
        else:
            raise ImportError(self.__ixNetworkSecureImportError)

    def _isConnected(self):
        if self.__ixNetworkSecure:
            return self.__ixNetworkLegacy._isConnected() or self.__ixNetworkSecure._isConnected()
        return self.__ixNetworkLegacy._isConnected()

    def _log(self, msg):
        if self._debug:
            dt = datetime.now().strftime("%a %b %d %X %Y")
            if (len(msg) > 1024):
                msg = ''.join([msg[:1024], '...'])
            print('[{timestamp}] [IxNet] [debug] {msg}'.format(timestamp=dt, msg=msg))

    def _is_ipv6(self, hostname):
        if len(hostname.split(':')) > 1:
            return True
        else:
            return False

    def _detectTransport(self, hostname, port= None):
        self._log("Detecting transport type...")
        
        _socket = None
        _transport = None
        _timeout = 15
        if port is None:
            port = 8009 
            usingDefaultPorts = True 
        else:
            usingDefaultPorts = False
        try:
            if self._is_ipv6(hostname):
                _socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _socket.settimeout(_timeout)
            _socket.setblocking(True)
            _socket.connect((hostname, port))
            read, write, error = select.select([_socket], [], [], _timeout)
            if len(read) > 0:
                response = _socket.recv(256).decode('ascii')
                self._log("Server responese: %s"%response)
                if response.startswith("<001") or "Server: IxNetwork API Server" in response or "Server: Connection Manager" in response:   
                    _transport = self.__ixNetworkLegacy
            else:
                _transport = self.__ixNetworkSecure
        except:
            if _socket:
                _socket.close()
                _socket = None
            if not usingDefaultPorts:
                e = sys.exc_info()[1]
                raise IxNetError('Unable to connect to {host}{port}. Error: {err}'.format(
                    host=hostname,
                    port=(':{0}'.format(port)),
                    err=str(e)))
        if _socket:
            _socket.close()
        if usingDefaultPorts and _transport is None:
           _transport = self.__ixNetworkSecure
        if _transport is None:
            if not usingDefaultPorts:
                raise IxNetError('Unable to connect to {host}{port}. Error: Host is unreachable'.format(host=hostname, port=(':{0}'.format(port))))
            else:
                raise IxNetError('Unable to connect to {host}{port}. Error: Host is unreachable'.format(host=hostname, port=(' using default ports (8009 or 443)')))
        self._log("Using transport type %s"%_transport._transportType)
        return _transport

    def setDebug(self, debug):
        self._debug = debug
        self.__ixNetworkLegacy.setDebug(debug)
        if self.__ixNetworkSecure:
            self.__ixNetworkSecure.setDebug(debug)
        return self

    def getRoot(self):
        return str('::ixNet::OBJ-/')

    def getNull(self):
        return str('::ixNet::OBJ-null')

    def setAsync(self):
        return self._getCurrentTransport().setAsync()

    def setTimeout(self, timeout):
        return self._getCurrentTransport().setTimeout(timeout)

    def getApiKey(self, hostname, *args):
        if not self.__ixNetworkSecure:
            print('Warning: Unable to get API key from {host} due to missing dependencies (see documentation for required dependencies). If you are trying to connect to a Windows IxNetwork API Server on TCL port you can safely ignore this warning.'.format(host=hostname))
            return self._noApiKey
        return self._getSecureTransport().getApiKey(hostname, *args)

    def getSessions(self, hostname, *args):
        return self._getSecureTransport().getSessions(hostname, *args)

    def clearSessions(self, hostname, *args):
        return self._getSecureTransport().clearSessions(hostname, *args)

    def clearSession(self, hostname, *args):
        return self._getSecureTransport().clearSession(hostname, *args)

    def getSessionInfo(self):
        return self._getCurrentTransport().getSessionInfo()
   
    def connect(self, hostname, *args):
        if self._isConnected() or self.__ixNetworkSecure is None:
            ret = self._getCurrentTransport().connect(hostname, *args)
        else:
            # we have secure lib loaded and need to identify the transport type
            nameValuePairs = {}
            name = None
            port = None
            for arg in args:
                if str(arg).startswith('-'):
                    if name is None:
                        name = str(arg)
                    else:
                        nameValuePairs[name] = ''
                elif name is not None:
                    nameValuePairs[name] = str(arg)
                    name = None
            if '-port' in nameValuePairs:
                port = int(nameValuePairs['-port'])
            ret = self._detectTransport(hostname, port).connect(hostname, *args)
        self._transportType = self._getCurrentTransport()._transportType
        return ret

    def disconnect(self):
        ret = self._getCurrentTransport().disconnect()
        self._transportType = None
        return ret

    def help(self, *args):
        return self._getCurrentTransport().help(*args)

    def setSessionParameter(self, *args):
        return self._getCurrentTransport().setSessionParameter(*args)

    def getVersion(self):
        if self._isConnected():
            return self._getCurrentTransport().getVersion()
        else:
            return self._version

    def getParent(self, objRef):
        return self._getCurrentTransport().getParent(objRef)

    def exists(self, objRef):
        return self._getCurrentTransport().exists(objRef)

    def commit(self):
        return self._getCurrentTransport().commit()

    def rollback(self):
        return self._getCurrentTransport().rollback()

    def execute(self, *args):
        return self._getCurrentTransport().execute(*args)

    def add(self, objRef, child, *args):
        return self._getCurrentTransport().add(objRef, child, *args)

    def remove(self, objRef):
        return self._getCurrentTransport().remove(objRef)

    def setAttribute(self, objRef, name, value):
        return self._getCurrentTransport().setAttribute(objRef, name, value)

    def setMultiAttribute(self, objRef, *args):
        return self._getCurrentTransport().setMultiAttribute(objRef, *args)

    def getAttribute(self, objRef, name):
        return self._getCurrentTransport().getAttribute(objRef, name)

    def getList(self, objRef, child):
        return self._getCurrentTransport().getList(objRef, child)

    def getFilteredList(self, objRef, child, name, value):
        return self._getCurrentTransport().getFilteredList(objRef, child, name, value)

    def adjustIndexes(self, objRef, object):
        return self._getCurrentTransport().adjustIndexes(objRef, object)

    def remapIds(self, localIdList):
        return self._getCurrentTransport().remapIds(localIdList)

    def getResult(self, resultId):
        return self._getCurrentTransport().getResult(resultId)

    def wait(self, resultId):
        return self._getCurrentTransport().wait(resultId)

    def isDone(self, resultId):
        return self._getCurrentTransport().isDone(resultId)

    def isSuccess(self, resultId):
        return self._getCurrentTransport().isSuccess(resultId)

    def writeTo(self, filename, *args):
        return self._getCurrentTransport().writeTo(filename, *args)

    def readFrom(self, filename, *args):
        return self._getCurrentTransport().readFrom(filename, *args)
