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

import getpass
import io
import os
import select
import socket
import sys
import time
from datetime import datetime

try:
    unicode = unicode
except NameError:
    unicode = str


from .IxNetwork import IxNetError


class IxNet:
    def __init__(self):
        self._root = str('::ixNet::OBJ-/')
        self._null = str('::ixNet::OBJ-null')
        self._socket = None
        self._address = None
        self._port = None
        self._sessionId = None
        self._serverusername = None
        self._proxySocket = None
        self._connectTokens = str()
        self._evalError = '1'
        self._evalSuccess = '0'
        self._evalResult = '0'
        self._addContentSeparator = 0
        self._firstItem = True
        self._sendContent = list()
        self._buffer = False
        self._sendBuffer = list()
        self._decoratedResult = list()
        self._filename = None
        self._debug = False
        self._async = False
        self._timeout = None
        self._transportType = 'TclSocket'
        self._OK = '::ixNet::OK'
        self._version = '9.00.1915.16'

    def setDebug(self, debug):
        self._debug = debug
        return self

    def getRoot(self):
        return self._root

    def getNull(self):
        return self._null

    def setAsync(self):
        self._async = True
        return self

    def setTimeout(self, timeout):
        self._timeout = timeout
        return self
        
    def _isConnected(self,raiseError=False):
        if self._socket is None:
            if raiseError is True:
                raise IxNetError('not connected')
            else:
                return False
        else:
            return True

    def _is_ipv6(self, hostname):
        if len(hostname.split(':')) > 1:
            return True
        else:
            return False

    def __initialConnect(self, address, port, options):
        # make an initial socket connection
        # this will keep trying as it could be connecting to the proxy
        # which may not have an available application instance at that time
        attempts = 0
        while True:
            try:
                if self._is_ipv6(address):
                    self._socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                else:
                    self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.connect((address, port))
                break
            except (socket.error,):
                if self._proxySocket is not None and attempts < 120:
                    time.sleep(2)
                    attempts += 1
                else:
                    self.__Close()
                    raise IxNetError(str(sys.exc_info()[1]))

        # a socket connection has been made now read the type of connection
        # setup to timeout if the remote endpoint is not valid
        self._socket.setblocking(0)
        read, write, error = select.select([self._socket], [], [], 30)
        if len(read) == 0 and len(write) == 0 and len(error) == 0:
            self.__Close()
            raise IxNetError('Connection handshake timed out after 30 seconds')
        self._socket.setblocking(1)

        # process the results from the endpoint
        try:
            connectString = self.__Recv()
            if connectString == 'proxy':
                self._socket.sendall(options.encode('ascii'))
                self._connectTokens = str(self.__Recv())
                connectTokens = dict(list(zip(self._connectTokens.split()[::2], self._connectTokens.split()[1::2])))
                print('connectiontoken is %s' %(connectTokens))
                self._proxySocket = self._socket
                self._socket = None
                self.__initialConnect(address, int(connectTokens['-port']), '')
        except:
                self.__Close()
                raise
                
    def connect(self, address, *args):
        try:
            if self._socket is not None:
                self.__SendRecv('ixNet', 'help')
        except:
            self.__Close()

        try:
            nameValuePairs = {}
            name = None
            serverusername = None
            sessionId = None
            for arg in args:
                if str(arg).startswith('-'):
                    if name is None:
                        name = str(arg)
                    else:
                        nameValuePairs[name] = ''
                elif name is not None:
                    nameValuePairs[name] = str(arg)
                    name = None
            if '-port' not in nameValuePairs:
                nameValuePairs['-port'] = 8009
            port = int(nameValuePairs['-port'])

            options = '-clientusername ' + getpass.getuser()
            if '-serverusername' in nameValuePairs:
                options += ' -serverusername ' + nameValuePairs['-serverusername']
                serverusername = nameValuePairs['-serverusername']
            if '-connectTimeout' in nameValuePairs:
                options += ' -connectTimeout ' + nameValuePairs['-connectTimeout']
            if '-applicationVersion' in nameValuePairs:
                options += ' -applicationVersion ' + nameValuePairs['-applicationVersion']
            if '-persistentApplicationVersion' in nameValuePairs:
                options += ' -persistentApplicationVersion ' + nameValuePairs['-persistentApplicationVersion']
            if '-forceVersion' in nameValuePairs:
                options += ' -forceVersion ' + nameValuePairs['-forceVersion']
            if '-closeServerOnDisconnect' in nameValuePairs:
                options += ' -closeServerOnDisconnect ' + nameValuePairs['-closeServerOnDisconnect']
            else:
                options += ' -closeServerOnDisconnect true'
            if '-sessionId' in nameValuePairs:
                options += ' -sessionId ' + nameValuePairs['-sessionId']
                sessionId = nameValuePairs['-sessionId']
            
            
            if self._socket is None:
                self.__initialConnect(address, port, options)
                conRes = self.__SendRecv('ixNet', 'connect', address, '-clientType', 'python', *args)
                self._CheckClientVersion()
                self._port = port
                self._address = address
                self._sessionId = self.getSessionId()
                self._serverusername = serverusername
                return conRes
            else:
                if (address != self._address or port != self._port):
                    return 'Cannot connect to {0}:{1} as a connection is already established to {2}:{3}. Please execute disconnect before trying this command again.'.format(address, port, self._address, self._port)
                elif sessionId and sessionId  != self._sessionId:
                    return 'Cannot connect to session {newId} as a connection is already established to session {currentId}. Please execute disconnect before trying this command again.'.format(newId=sessionId, currentId=self._sessionId)
                elif serverusername and serverusername  != self._serverusername:
                    return 'Cannot connect to a session associated with {newUsername} as a connection is already established to a session associated with {currentUsername}. Please execute disconnect before trying this command again.'.format(newUsername=serverusername, currentUsername=self._serverusername)
                else:
                    return self._OK
        except:
            e = sys.exc_info()[1]
            self.__Close()
            raise IxNetError('Unable to connect to %s:%s. Error: %s' % (str(address), str(nameValuePairs['-port']), str(e)))

    def disconnect(self):
        if self._socket is None:
            return 'not connected'
        else:
            response = self.__SendRecv('ixNet', 'disconnect')
            self.__Close()
            return response

    def help(self, *args):
        return self.__SendRecv('ixNet', 'help', *args)

    def getSessionInfo(self):
        self._isConnected(raiseError=True)
        if self._proxySocket:
            backendType = 'connectionmanager'
        else:
            backendType = 'ixnetwork'   
        return {'id': self.getSessionId(),
                'port' : self._port,
                'applicationType': 'ixntcl',
                'backendType': backendType,
                'state': 'active',
                'inUse': True
                }

    def setSessionParameter(self, *args):
        if len(args) % 2 == 0:
            return self.__SendRecv('ixNet', 'setSessionParameter', *args)
        else:
            raise IxNetError('setSessionParameter requires an even number of name/value pairs')

    def getSessionId(self):
        self._isConnected(raiseError=True)
        result = self.__SendRecv('ixNet', 'setSessionParameter')
        if isinstance(result, list) and 'sessionId' in result and len(result) > result.index("sessionId"):
            return result[1+result.index("sessionId")] 
        return  -1
        
    def getVersion(self):
        if self._socket is None:
            return self._version
        else:
            return self.__SendRecv('ixNet', 'getVersion')

    def getParent(self, objRef):
        return self.__SendRecv('ixNet', 'getParent', objRef)

    def exists(self, objRef):
        return self.__SendRecv('ixNet', 'exists', self.__CheckObjRef(objRef))

    def commit(self):
        return self.__SendRecv('ixNet', 'commit')

    def rollback(self):
        return self.__SendRecv('ixNet', 'rollback')

    def execute(self, *args):
        return self.__SendRecv('ixNet', 'exec', *args)

    def add(self, objRef, child, *args):
        return self.__SendRecv('ixNet', 'add', self.__CheckObjRef(objRef), child, *args)

    def remove(self, objRef):
        return self.__SendRecv('ixNet', 'remove', objRef)

    def setAttribute(self, objRef, name, value):
        self._buffer = True
        return self.__SendRecv('ixNet', 'setAttribute', self.__CheckObjRef(objRef), name, value)

    def setMultiAttribute(self, objRef, *args):
        self._buffer = True
        return self.__SendRecv('ixNet', 'setMultiAttribute', self.__CheckObjRef(objRef), *args)

    def getAttribute(self, objRef, name):
        return self.__SendRecv('ixNet', 'getAttribute', self.__CheckObjRef(objRef), name)

    def getList(self, objRef, child):
        return self.__SendRecv('ixNet', 'getList', self.__CheckObjRef(objRef), child)

    def getFilteredList(self, objRef, child, name, value):
        return self.__SendRecv('ixNet', 'getFilteredList', self.__CheckObjRef(objRef), child, name, value)

    def adjustIndexes(self, objRef, object):
        return self.__SendRecv('ixNet', 'adjustIndexes', self.__CheckObjRef(objRef), object)

    def remapIds(self, localIdList):
        if type(localIdList) is tuple:
            localIdList = list(localIdList)
        return self.__SendRecv('ixNet', 'remapIds', localIdList)

    def getResult(self, resultId):
        return self.__SendRecv('ixNet', 'getResult', resultId)

    def wait(self, resultId):
        return self.__SendRecv('ixNet', 'wait', resultId)

    def isDone(self, resultId):
        return self.__SendRecv('ixNet', 'isDone', resultId)

    def isSuccess(self, resultId):
        return self.__SendRecv('ixNet', 'isSuccess', resultId)

    def writeTo(self, filename, *args):
        if any(arg == '-ixNetRelative' for arg in args):
            return self.__SendRecv('ixNet', 'writeTo', filename, '\02'.join(args))
        else:
            return self.__CreateFileOnServer(filename)

    def readFrom(self, filename, *args):
        if any(arg == '-ixNetRelative' for arg in args):
            return self.__SendRecv('ixNet', 'readFrom', filename, '\02'.join(args))
        else:
            return self.__PutFileOnServer(filename)

    def __CheckObjRef(self, objRef):
        if (type(objRef) in (str, unicode)) is False:
            raise IxNetError('The objRef parameter must be ' + str(str) + ' instead of ' + str(type(objRef)))
        else:
            return objRef

    def __PutFileOnServer(self, filename):
        fid = None
        try:
            fid = io.open(filename, 'rb')
            self.__Send('<001><005><007{0}>{1}<009{2}>'.format(len(filename), filename, os.path.getsize(filename)))
            self.__SendBinary(fid.read())
        finally:
            if fid is not None:
                fid.close()
        remoteFilename = self.__Recv()
        return self.__SendRecv('ixNet', 'readFrom', remoteFilename, '-ixNetRelative')

    def __CreateFileOnServer(self, filename):
        self.__Send('<001><006><007{0}>{1}<009>'.format(len(filename), filename))
        remoteFilename = self.__Recv()
        return self.__SendRecv('ixNet', 'writeTo', remoteFilename, '-ixNetRelative', '-overwrite')

    def __Close(self):
        try:
            if self._socket:
                self._socket.close()
        except Exception:
            sys.exc_clear()
        try:
            if self._proxySocket:
                self._proxySocket.close()
        except Exception:
            sys.exc_clear()
        self._socket = None
        self._address = None
        self._port = None
        self._sessionId = None
        self._serverusername = None
        self._proxySocket = None

    def __Join(self, *args):
        for arg in args:
            if type(arg) is list or type(arg) is tuple:
                if self._addContentSeparator == 0:
                    self._sendContent.append('\02')
                if self._addContentSeparator > 0:
                    self._sendContent.append('{')
                self._addContentSeparator += 1
                self._firstItem = True
                if len(arg) == 0:
                    self._sendContent.append('{}')
                else:
                    for item in arg:
                        self.__Join(item)
                if self._addContentSeparator > 1:
                    self._sendContent.append('}')
                self._addContentSeparator -= 1
            else:
                if self._addContentSeparator == 0 and len(self._sendContent) > 0:
                    self._sendContent.append('\02')
                elif self._addContentSeparator > 0:
                    if self._firstItem is False:
                        self._sendContent.append(' ')
                    else:
                        self._firstItem = False
                if arg is None:
                    arg = ''
                elif type(arg) != str:
                    arg = str(arg)
                if len(arg) == 0 and len(self._sendContent) > 0:
                    self._sendContent.append('{}')
                elif arg.find(' ') != -1 and self._addContentSeparator > 0:
                    self._sendContent.append('{'+arg+'}')
                else:
                    self._sendContent.append(arg)

        return

    def __SendRecv(self, *args):
        if self._socket is None:
            raise IxNetError('not connected')

        self._addContentSeparator = 0
        self._firstItem = True

        argList = list(args)

        if self._async:
            argList.insert(1, '-async')

        if self._timeout is not None:
            argList.insert(1, '-timeout')
            argList.insert(2, self._timeout)

        for item in argList:
            self.__Join(item)

        self._sendContent.append('\03')
        self._sendBuffer.append(''.join(self._sendContent))
        if self._buffer is False:
            buffer = ''.join(self._sendBuffer)
            self._log('Sending: {0}'.format(buffer))
            self.__Send('<001><002><009{0}>{1}'.format(len(buffer), buffer))
            self._sendBuffer = list()

        self._async = False
        self._timeout = None
        self._buffer = False
        self._sendContent = list()

        if len(self._sendBuffer) > 0:
            return self._OK
        else:
            return self.__Recv()

    def __Send(self, content):
        if self._socket is None:
            raise IxNetError('not connected')
        else:
            try:
                if type(content) is str:
                    content = content.encode('ascii')
                self._socket.sendall(content)
            except (socket.error,):
                e = sys.exc_info()[1]
                self.__Close()
                raise IxNetError('Error:' + str(e))

    def __SendBinary(self, content):
        if self._socket is None:
            raise IxNetError('not connected')
        else:
            try:
                self._socket.sendall(content)
            except (socket.error,):
                e = sys.exc_info()[1]
                self.__Close()
                raise IxNetError('Error:' + str(e))

    def __Recv(self):
        self._decoratedResult = list()
        responseBuffer = str()
        try:
            while True:
                responseBuffer = str()
                commandId = None
                contentLength = int(0)

                while True:
                    responseBuffer += self._socket.recv(1).decode('ascii')
                    startIndex = int(responseBuffer.find('<'))
                    stopIndex = int(responseBuffer.find('>'))
                    if startIndex != -1 and stopIndex != -1:
                        commandId = int(responseBuffer[startIndex + 1:startIndex + 4])
                        if startIndex + 4 < stopIndex:
                            contentLength = int(responseBuffer[startIndex + 4:stopIndex])
                        break

                if commandId == 1:
                    self._evalResult = self._evalError
                    self._socket.recv(contentLength)
                elif commandId == 3:
                    self._socket.recv(contentLength)
                elif commandId == 4:
                    self._evalResult = self._socket.recv(contentLength).decode('ascii')
                elif commandId == 7:
                    self._filename = self._socket.recv(contentLength).decode('ascii')
                elif commandId == 8:
                    binaryFile = None
                    try:
                        binaryFile = io.open(self._filename, 'w+b')
                        chunk = bytearray()
                        bytesToRead = 32767
                        while contentLength > 0:
                            if contentLength < bytesToRead:
                                bytesToRead = contentLength
                            chunk = self._socket.recv(bytesToRead)
                            binaryFile.write(chunk)
                            contentLength -= len(chunk)
                    finally:
                        if binaryFile is not None:
                            binaryFile.close()
                elif commandId == 9:
                    self._decoratedResult = list()
                    chunk = str()
                    bytesToRead = 32767
                    while contentLength > 0:
                        if contentLength < bytesToRead:
                            bytesToRead = contentLength
                        chunk = self._socket.recv(bytesToRead).decode('ascii')
                        self._decoratedResult.append(chunk)
                        contentLength -= len(chunk)
                    break

        except (socket.error,):
            e = sys.exc_info()[1]
            self.__Close()
            raise IxNetError('Recv failed. Error:' + str(e))

        self._log('Received: {0}'.format(''.join(self._decoratedResult)))

        if self._evalResult == self._evalError:
            raise IxNetError(''.join(self._decoratedResult))

        if len(self._decoratedResult) > 0 and self._decoratedResult[0].startswith('\01'):
            self._decoratedResult[0] = self._decoratedResult[0].replace('\01', '')
            try :
                return eval(''.join(self._decoratedResult))
            except :
                self._decoratedResult[0] = self._decoratedResult[0].replace('\01', '').replace('\r\\n', '')
                return eval(''.join(self._decoratedResult))
        else:
            return ''.join(self._decoratedResult)

    def _CheckClientVersion(self):
        if self._version != self.getVersion():
            print('WARNING: IxNetwork Python library version {0} is not matching the IxNetwork client version {1}'.format(self._version, self.getVersion()))


    def _log(self, msg):
        if self._debug:
            dt = datetime.now().strftime("%a %b %d %X %Y")
            if (len(msg) > 1024):
                msg = ''.join([msg[:1024], '...'])
            print('[{timestamp}] [IxNet] [debug] {msg}'.format(timestamp=dt, msg=msg))