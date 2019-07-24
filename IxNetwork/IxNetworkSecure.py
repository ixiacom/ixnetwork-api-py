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
import re
import sys
import time
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'dependencies')))

from datetime import datetime
try:
    from urllib import quote
except ImportError:
    from urllib.parse import quote

missingDependencies = []

try: import ssl
except ImportError: raise ImportError('You are using a Python version without SSL support (possible cause: python might have been compiled without ssl or openssl libs are missing). Please check Python documentation for SSL configuration.')

try: import requests
except ImportError: missingDependencies.append('requests')

try: 
    from websocket import create_connection
    create_websocket_connection = create_connection
except ImportError: missingDependencies.append('websocket-client')

if not (hasattr(ssl, 'SSLContext') and hasattr(ssl.SSLContext, 'check_hostname')):
    if hasattr(ssl, "match_hostname"):
        from ssl import match_hostname
    else:
        try:
            from backports.ssl_match_hostname import match_hostname
        except ImportError:
            missingDependencies.append('backports.ssl-match-hostname')    
        try:
            import backports.ssl.monkey 
            monkey = backports.ssl.monkey
            monkey.patch()
        except:
            missingDependencies.append('backports.ssl')
try: 
    import urllib3
    try:
        import urllib3.contrib.pyopenssl as pyopenssl
        pyopenssl.inject_into_urllib3()
    except :
        missingDependencies.append('pyopenssl')
except ImportError: 
    missingDependencies.append('urllib3')  

if 'urllib3' not in missingDependencies and 'requests' not in missingDependencies:
    if sys.version_info[0] == 2 and ((sys.version_info[1] == 7 and sys.version_info[2] < 9) or sys.version_info[1] < 7):
        import requests.packages.urllib3
        try:
            requests.packages.urllib3.disable_warnings()
        except AttributeError:
            raise ImportError('You are using an old urllib3 version which does not support handling the certificate validation warnings. Please upgrade urllib3 using: pip install urllib3 --upgrade')
        if 'backports.ssl' not in missingDependencies and hasattr(urllib3.util, 'IS_PYOPENSSL') and not urllib3.util.IS_PYOPENSSL:
            if 'pyopenssl' not in missingDependencies :
                missingDependencies.append('pyopenssl')
    else:
        try:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except AttributeError:
            raise ImportError('You are using an old urllib3 version which does not support handling the certificate validation warnings. Please upgrade urllib3 using: pip install urllib3 --upgrade')
if len(missingDependencies) > 0:
    raise ImportError('Cannot load required dependencies: {0}.\nPlease run pip install -r requirements.txt.'.format(', '.join(missingDependencies)))
missingDependencies = None

try: unicode = unicode
except NameError: unicode = str

from .IxNetwork import IxNetError 

class IxNetAuthenticationError(Exception):
    '''IxNet authentication error'''

class IxNet(object):
    """
    Set the IxNet object up
    """

    def __init__(self):
        self._debug = None
        self._setDefaults()

    def _setDefaults(self):
        self._websocket = None
        self._headers = {}
        self._evalError = '1'
        self._evalSuccess = '0'
        self._evalResult = '0'
        self._addContentSeparator = 0
        self._firstItem = True
        self._sendContent = list()
        self._buffer = False
        self._sendBuffer = list()
        self._decoratedResult = list()
        self._noApiKey = '00000000000000000000000000000000'
        self._async = False
        self._timeout = None
        self._transportType = 'WebSocket'
        self._version = '9.00.1915.16'
        self.OK = '::ixNet::OK'
        self.ERROR = '::ixNet::ERROR'
        self.VERIFY_CERT = False
        # session parameters
        self._connectionInfo = {
            'port': None,
            'verb': None,
            'wsVerb': None,
            'hostname': None,
            'url': None,
            'sessionUrl': None,
            'restUrl': None,
            'wsUrl': None,
            'sessionId': None,
            'backendType': None,
            'applicationType': None,
            'closeServerOnDisconnect': None,
            'serverUsername': None
        }

        self._initialPort = None
        self._initialHostname = None


    def setDebug(self, debug):
        self._debug = debug
        return self

    def getRoot(self):
        return str('::ixNet::OBJ-/')

    def getNull(self):
        return str('::ixNet::OBJ-null')

    def setAsync(self):
        self._async = True
        return self

    def setTimeout(self, timeout):
        self._timeout = timeout
        return self

    def getApiKey(self, hostname, *args):
        defaultArgs = {
            '-apiKeyFile': 'api.key',
            '-port': '443',
        }
        sessionArgs = self._getArgMap(defaultArgs, *args)

        port = sessionArgs['-port']
        apiKeyFile = sessionArgs['-apiKeyFile']
        url = 'https://{hostname}:{port}/api/v1/auth/session'.format(hostname=self._ip_encloser(hostname), port=port)
        if not self._isConnected(raiseError=False):
            self._createHeaders()

        username = password = ''
        if (not sessionArgs.get('-username')) or (not sessionArgs.get('-password')):
            if len(args) >= 2:
                username = args[0]
                password = args[1]
        else:
            username = sessionArgs['-username']
            password = sessionArgs['-password']

        try:
            auth = self._restSend('POST', url, payload={'username': username, 'password': password}, timeout=180)
        except IxNetAuthenticationError:
            e = sys.exc_info()[1]
            msg = 'Unable to get API key from {host}:{port}. Error: IxNetAuthenticationError: {err}.\n'.format(host=hostname, port=port, err=e.args[0])
            msg += 'Please check the getApiKey command arguments.\n '
            msg += 'An example of a correct method call is:\n\t'
            msg += 'ixNet.getApiKey(<hostname>, "-username", <username>, "-password", <password> [,"-port", <443>] [, "-apiKeyFile", <api.key>])'
            raise IxNetError(msg)
        except:
            raise IxNetError('Unable to get API key from {host}:{port}.'.format(host=hostname, port=port))

        if os.path.isabs(apiKeyFile):
            apiKeyPath = self._tryWriteAPIKey(apiKeyFile, auth.apiKey)
        else:
            cwd = os.getcwd()
            libraryDir = os.path.dirname(os.path.abspath(__file__))
            apiKeyPath = self._tryWriteAPIKey(os.path.join(cwd, apiKeyFile), auth.apiKey) or \
                         self._tryWriteAPIKey(os.path.join(libraryDir, apiKeyFile), auth.apiKey)

        if apiKeyPath:
            self._log('The API key was saved at: {0}'.format(apiKeyPath))
        else:
            self._log('Could not save API key to disk.')

        return auth.apiKey

    def getSessions(self, hostname, *args):
        if not self._isConnected(raiseError=False):
            if not self._connectionInfo['url']:
                # if we have not established a websocket connection, we need to
                # populate the headers
                # and create the baseURL (host:port/api/v1/sessions)
                defaultArgs = {
                    '-apiKey': '',
                    '-apiKeyFile': 'api.key',
                    '-port': '443'
                }
                sessionArgs = self._getArgMap(defaultArgs, *args)
                self._createHeaders(apiKey=sessionArgs.get('-apiKey'), apiKeyFile=sessionArgs.get('-apiKeyFile'))
                baseURL = self._getBaseUrl(hostname, sessionArgs)
                port = sessionArgs.get('-port')
            else:
                baseURL = self._connectionInfo['url']
                port = self._connectionInfo['port']
        else:
            sessionArgs = self._getArgMap({'-port': '443'}, *args)
            port = sessionArgs.get('-port')
            baseURL = self._connectionInfo['url']

            if (hostname != self._initialHostname and hostname != self._connectionInfo['hostname']) or \
                    (port != self._initialPort and port != self._connectionInfo['port']):
                raise IxNetError('A connection has already been established to {initialHostname}:{initialPort}. In order to query {hostname}:{port} you must first disconnect.'.format(initialHostname=self._connectionInfo['hostname'],
                    initialPort=self._connectionInfo['port'],
                    hostname=hostname,
                    port=port))

        response = self._restSend('GET', baseURL)
        sessions = dict()
        if isinstance(response, list) is False:
            response = [response]
        for session in response:
            if str(session.applicationType).lower() == 'ixnrest' or self._tryGetAttr(session, 'backendType', default='LinuxAPIServer').lower() == 'ixnetwork':
                sessions[session.id] = self._getDetailedSessionInfo(session, baseURL, port)
        return sessions

    def clearSessions(self, hostname, *args):
        deleted_sessions = []
        sessions = self.getSessions(hostname, *args)
        for sessionId in sessions:
            session = sessions[sessionId]
            if session['backendType'] != 'ixnetwork' and session['state'] == 'active' and not self._parseAsBool(session['inUse']):
                self._cleanUpSession(session['sessionUrl'])
                deleted_sessions.append(session['sessionUrl'])
        return deleted_sessions

    def clearSession(self, hostname, *args):
        defaultArgs = {
            '-apiKey': '',
            '-apiKeyFile': 'api.key',
            '-sessionId': '',
            '-port': '443',
            '-force': False
        }
        operationArgs = self._getArgMap(defaultArgs, *args)
        id = operationArgs['-sessionId']
        if not id:
            raise IxNetError('A session ID must be provided in order to clear a specific session.')

        sessions = self.getSessions(hostname, *args)
        try:
            session = sessions.get(int(id))
        except ValueError:
            raise IxNetError('{id} is not a proper value for a session ID.'.format(id=id))
        
        if not session:
            raise IxNetError("Session {id} cannot be found in the list of sessions IDs: {sessions}.".format(id=id, sessions=','.join(map(str, sessions.keys()))))
            
            

        if operationArgs['-force'] and session['state'] == 'initial':
                self._restSend('POST', '{url}/{action}'.format(url=session['sessionUrl'], action='operations/start'))
                self._waitForState('active', session['sessionUrl'])
                self._cleanUpSession(session['sessionUrl'])
                return self.OK
        elif (session['state'] == 'active' and (operationArgs['-force'] or not self._parseAsBool(session['inUse']))):
            if session['backendType'] == 'ixnetwork':
                return "Clearing IxNetwork standalone sessions is not supported."
            elif (self._isConnected() and self._connectionInfo['sessionId'] == id):
                self._connectionInfo['closeServerOnDisconnect'] = True
                return self.disconnect()
            else:
                self._cleanUpSession(session['sessionUrl'])
                return  self.OK
        elif operationArgs['-force'] and session['state'] == 'stopped':
            self._deleteSession(session['sessionUrl'])
            return self.OK
        raise IxNetError("Session {id} cannot be cleared as it is currently in {state} state. Please specify -force true if you want to forcefully clear in use sessions.".format(id=id,state=session['state']))

    def getSessionInfo(self):
        self._isConnected(raiseError=True)
        session = self._restSend('GET', '{0}'.format(self._connectionInfo['sessionUrl']))
        return self._getDetailedSessionInfo(session)

    def connect(self, hostname, *args):
        default_args = {
            '-sessionId': 0,
            '-clientId': 'python',
            '-version': '5.30',
            '-connectTimeout': 450,
            '-allowOnlyOneConnection': False,
            '-apiKey': '',
            '-apiKeyFile': 'api.key',
            '-product': 'ixnrest',
            '-clientusername' : getpass.getuser(),
            '-serverusername': None
        }

        connectArgs = self._getArgMap(default_args, *args)
        connectArgs['-sessionId'] = int(connectArgs['-sessionId'])
        connectArgs['-connectTimeout'] = int(connectArgs['-connectTimeout'])
        connectArgs['-allowOnlyOneConnection'] = self._parseAsBool(connectArgs['-allowOnlyOneConnection'])

        if self._isConnected(raiseError=False):
            port = connectArgs.get('-port', '443')
            if (hostname != self._initialHostname and hostname != self._connectionInfo['hostname']) or \
                    (port != self._initialPort and port != self._connectionInfo['port']):
                return 'Cannot connect to {0}:{1} as a connection is already established to {2}:{3}. Please execute disconnect before trying this command again.'.format(hostname, port, self._connectionInfo['hostname'], self._connectionInfo['port'])
            elif connectArgs['-sessionId'] and connectArgs['-sessionId'] != self._connectionInfo['sessionId']:
                return 'Cannot connect to session {newId} as a connection is already established to session {currentId}. Please execute disconnect before trying this command again.'.format(newId=connectArgs['-sessionId'], currentId=self._connectionInfo['sessionId'])
            elif connectArgs['-serverusername'] and self._connectionInfo['backendType'] != 'ixnetwork' and connectArgs['-serverusername'] != self._connectionInfo['serverUsername']:
                return 'Cannot connect to a session associated with {newUsername} as a connection is already established to a session associated with {currentUsername}. Please execute disconnect before trying this command again.'.format(newUsername=connectArgs['-serverusername'], currentUsername=self._connectionInfo['serverUsername'])
            else:
                return self.OK

        self._createHeaders(apiKey=connectArgs.get('-apiKey'), apiKeyFile=connectArgs.get('-apiKeyFile'))

        self._getBaseUrl(hostname, connectArgs, store=True)
        try:
            if connectArgs['-sessionId'] < 1 and connectArgs['-serverusername'] is None:
                session = self._restSend('POST', self._connectionInfo['url'], {"applicationType": connectArgs['-product']})
            else:
                sessions = self.getSessions(self._initialHostname, args)
                session = lambda: None
                if connectArgs['-serverusername'] is not None:
                    matchedSessions = {}
                    for key, value in sessions.items():
                         if value['userName'].lower() == connectArgs['-serverusername'].lower():
                             matchedSessions[key] = value
                    sessions = matchedSessions
                    if not sessions:
                        raise Exception('There are no sessions available with the serverusername {serverusername}.'.format(serverusername=connectArgs['-serverusername']))
                    if connectArgs['-sessionId'] < 1:
                        if (len(sessions) > 1):
                            raise Exception('There are multiple sessions available with the serverusername {serverusername}. Please specify -sessionId also.'.format(serverusername=connectArgs['-serverusername']))
                        else:
                            connectArgs['-sessionId'] = list(sessions.keys())[0]
                if connectArgs['-sessionId'] not in sessions:
                    raise Exception('Invalid sessionId value ({id}).'.format(id=connectArgs['-sessionId']))
                session.__dict__ = sessions[connectArgs['-sessionId']]
                if session.inUse and 'HLAPI' not in connectArgs.get('-clientId'):
                    if (self._tryGetAttr(session, 'backendType', default='LinuxAPIServer').lower() == 'connectionmanager') or connectArgs['-allowOnlyOneConnection']:
                        self._connectionInfo['closeServerOnDisconnect'] = False
                        raise Exception('The requested session is currently in use.')
                    else:
                        print('Warning: you are connecting to session {id} which is in use.'.format(id=session.id))

            self._connectionInfo['applicationType'] = session.applicationType
            closeServerOnDisconnectBool = None
            
            if not '-closeServerOnDisconnect' in connectArgs:
                if self._connectionInfo['applicationType'] == 'ixnrest':
                    closeServerOnDisconnectBool = 'true'
                else:
                    closeServerOnDisconnectBool = 'false'
            else: 
                if self._parseAsBool(connectArgs.get('-closeServerOnDisconnect')):
                    closeServerOnDisconnectBool = 'true'
                else:
                    closeServerOnDisconnectBool = 'false'

            self._connectionInfo['closeServerOnDisconnect'] = self._parseAsBool(closeServerOnDisconnectBool)
            self._connectionInfo['sessionId'] = session.id
            self._connectionInfo['sessionUrl'] = '{url}/{id}'.format(url=self._connectionInfo['url'], id=self._connectionInfo['sessionId'])
            self._connectionInfo['backendType'] = self._tryGetAttr(session, 'backendType', default='LinuxAPIServer')
            self._connectionInfo['wsUrl'] = '{websocket}://{hostname}:{port}/ixnetworkweb/ixnrest/ws/api/v1/sessions/{id}/ixnetwork/globals/ixnet?closeServerOnDisconnect={closeServerOnDisconnect}&clientType={clientType}&clientUsername={clientusername}'.format(websocket=self._connectionInfo['wsVerb'],
                                                hostname=self._ip_encloser(self._connectionInfo['hostname']),
                                                port=self._connectionInfo['port'],
                                                id=self._connectionInfo['sessionId'],
                                                closeServerOnDisconnect= self._connectionInfo['closeServerOnDisconnect'],
                                                clientType = connectArgs.get('-clientId'),
                                                clientusername = connectArgs['-clientusername'])

            self._connectionInfo['restUrl'] = '{url}/ixnetwork'.format(url=self._connectionInfo['sessionUrl'])
            self._connectionInfo['serverusername'] = self._tryGetAttr(session, 'userName', 'Unknown')
            self._connectionInfo['startTime'] = datetime.now().strftime("%Y%m%d_%X")
            self._connectionInfo['serverUsername'] = session.userName


            if str(session.state).lower() == 'initial' or str(session.state).lower() == 'stopped':
                self._restSend('POST', '{url}/{action}'.format(url=self._connectionInfo['sessionUrl'], action='operations/start'), payload={'applicationType': connectArgs['-product']})
            self._waitForState('active', self._connectionInfo['sessionUrl'], timeout=connectArgs['-connectTimeout'])

            options = {
                'sslopt': {
                    'cert_reqs': ssl.CERT_NONE,
                    'check_hostname': False
                }
            }

            if self._parseAsBool(connectArgs['-allowOnlyOneConnection']):
                    self._isSessionAvailable(session=session, raiseError=True)

            self._websocket = create_websocket_connection(self._connectionInfo['wsUrl'], **options)
            self._websocket.settimeout(900)
            result = self._sendRecv('ixNet', 'connect',
                '-version', connectArgs['-version'],
                '-clientType', 'python',
                '-clientId', connectArgs.get('-clientId'),
                '-closeServerOnDisconnect', closeServerOnDisconnectBool,
                '-clientUsername', connectArgs['-clientusername'],
                '-apiKey', self._headers['X-Api-Key'])

            self._checkClientVersion()

            return result
        except:
            e = sys.exc_info()[1]
            if self._connectionInfo['sessionUrl'] and self._connectionInfo['closeServerOnDisconnect']:
                self._cleanUpSession(self._connectionInfo['sessionUrl'])
            self._close()
            self._deleteSession(self._connectionInfo['sessionUrl'])
            portValueString = ''
            if '-port' in connectArgs:
                portValueString = connectArgs['-port']
            else:
                portValueString = '443'
            self._setDefaults()
            raise IxNetError('Unable to connect to {host}{port}. Error: {ixNetError}: {err}'.format(host=hostname,
                       port= ':{0}'.format(portValueString),
                       ixNetError=self.ERROR,
                       err=str(e)))

    def disconnect(self):
        if self._isConnected():
            self._close()
            # bye, bye self._cleanUpSession() forever 
            #if self._connectionInfo['closeServerOnDisconnect']:
            #    self._cleanUpSession(self._connectionInfo['sessionUrl']) 
            self._setDefaults()
        else:
            return 'not connected'
        return self.OK

    def help(self, *args):
        return self._sendRecv('ixNet', 'help', *args)

    def setSessionParameter(self, *args):
        if len(args) % 2 == 0:
            return self._sendRecv('ixNet', 'setSessionParameter', *args)
        else:
            raise IxNetError('setSessionParameter requires an even number of name/value pairs')

    def getVersion(self):
        if self._isConnected():
            return self._sendRecv('ixNet', 'getVersion')
        else:
            return self._version

    def getParent(self, objRef):
        return self._sendRecv('ixNet', 'getParent', objRef)

    def exists(self, objRef):
        return self._sendRecv('ixNet', 'exists', self._checkObjRef(objRef))

    def commit(self):
        return self._sendRecv('ixNet', 'commit')

    def rollback(self):
        return self._sendRecv('ixNet', 'rollback')

    def execute(self, *args):
        return self._sendRecv('ixNet', 'exec', *args)

    def add(self, objRef, child, *args):
        return self._sendRecv('ixNet', 'add', self._checkObjRef(objRef), child, *args)

    def remove(self, objRef):
        return self._sendRecv('ixNet', 'remove', objRef)

    def setAttribute(self, objRef, name, value):
        self._buffer = True
        return self._sendRecv('ixNet', 'setAttribute', self._checkObjRef(objRef), name, value)

    def setMultiAttribute(self, objRef, *args):
        self._buffer = True
        return self._sendRecv('ixNet', 'setMultiAttribute', self._checkObjRef(objRef), *args)

    def getAttribute(self, objRef, name):
        return self._sendRecv('ixNet', 'getAttribute', self._checkObjRef(objRef), name)

    def getList(self, objRef, child):
        return self._sendRecv('ixNet', 'getList', self._checkObjRef(objRef), child)

    def getFilteredList(self, objRef, child, name, value):
        return self._sendRecv('ixNet', 'getFilteredList', self._checkObjRef(objRef), child, name, value)

    def adjustIndexes(self, objRef, object):
        return self._sendRecv('ixNet', 'adjustIndexes', self._checkObjRef(objRef), object)

    def remapIds(self, localIdList):
        if isinstance(localIdList, type(())):
            localIdList = list(localIdList)
        return self._sendRecv('ixNet', 'remapIds', localIdList)

    def getResult(self, resultId):
        return self._sendRecv('ixNet', 'getResult', resultId)

    def wait(self, resultId):
        return self._sendRecv('ixNet', 'wait', resultId)

    def isDone(self, resultId):
        return self._sendRecv('ixNet', 'isDone', resultId)

    def isSuccess(self, resultId):
        return self._sendRecv('ixNet', 'isSuccess', resultId)

    def writeTo(self, filename, *args):
        if '-ixNetRelative' in args:
            return self._sendRecv('ixNet', 'writeTo', filename, '\02'.join([str(x) for x in args]))
        else:
            return self._createFileOnServer(filename)

    def readFrom(self, filename, *args):
        if '-ixNetRelative' in args:
            return self._sendRecv('ixNet', 'readFrom', filename, '\02'.join([str(x) for x in args]))
        else:
            return self._putFileOnServer(filename)

    def _formatAsIxNetError(self, msg):
        return "{0} - {1}".format(self.ERROR, msg)
    
    def _tryWriteAPIKey(self, dstFile, key):
        try:
            f = open(dstFile, 'w')
            try:
                f.write(key)
            finally:
                f.close()
        except IOError:
            return None

        return dstFile

    def _tryReadAPIKey(self, dstFile):
        key = None

        try:
            f = open(dstFile, 'r')
            try: 
                key = f.read()
            finally:
                f.close()
        except IOError:
            return None

        return key

    def _createHeaders(self, apiKey=None, apiKeyFile=None):
        apiKeyValue = self._noApiKey

        if apiKey:
            apiKeyValue = apiKey
        elif apiKeyFile:
            if os.path.isabs(apiKeyFile):
                apiKeyValue = self._tryReadAPIKey(apiKeyFile) or apiKeyValue
            else:
                cwd = os.getcwd()
                libraryDir = os.path.dirname(os.path.abspath(__file__))
                apiKeyValue = self._tryReadAPIKey(os.path.join(cwd, apiKeyFile)) or \
                              self._tryReadAPIKey(os.path.join(libraryDir, apiKeyFile)) or apiKeyValue

        self._headers = {
            'IxNetwork-Lib': 'IxNetwork python client v.' +self._version,
            'X-Api-Key': apiKeyValue,
            'Content-Type': 'application/json'
        }

    def _ip_encloser(self, hostname):
        if len(hostname.split(':')) > 1:
            return '[{hostname}]'.format(hostname=hostname)
        else:
            return hostname 
    
    def _createUrl(self, verb, hostname, port):
        return '{verb}{verbSeparator}{hostname}{portSeparator}{port}/api/v1/sessions'.format(verb=verb,
                                                                verbSeparator='://',
                                                                hostname=self._ip_encloser(hostname),
                                                                portSeparator=':',
                                                                port=port)

    def _setConnectionInfo(self, verb, hostname, port, url):
        self._connectionInfo['verb'] = verb

        self._connectionInfo['wsVerb'] = ''
        if verb == 'http':
            self._connectionInfo['wsVerb'] = 'ws' 
        else:
            self._connectionInfo['wsVerb'] = 'wss'
        m = re.match('\[(?P<hostname>.*)\]', hostname)
        if m:
            self._connectionInfo['hostname'] = m.group('hostname')
        else:
            self._connectionInfo['hostname'] = hostname
        self._connectionInfo['port'] = port
        self._connectionInfo['url'] = url

    def _getBaseUrl(self, hostname, connectArgs, store=False):
        if '-port' in connectArgs:
            params = [('https', connectArgs['-port']), ('http', connectArgs['-port'])]
        else:
            params = [('https', 443)]

        attempts = 0
        for connectionParams in params:
            url = self._createUrl(connectionParams[0], hostname, connectionParams[1])

            try:
                url = self._restGetRedirect(url, timeout=30)
                if store:
                    m = re.match('(?P<verb>https?)://(?P<hostname>[^/]+):(?P<port>\d+)', url)
                    if m:
                        port = m.group('port')
                    else:
                        m = re.match('(?P<verb>https?)://(?P<hostname>[^/:]+)', url)
                        port = 443
                        if m.group('verb') == 'http':
                            port = 80  

                    self._setConnectionInfo(m.group('verb'), m.group('hostname'), port, url)

                    self._initialPort = connectArgs.get('-port', 443)
                    self._initialHostname = hostname
                break
            except IxNetAuthenticationError:
                raise IxNetError('The API key is either missing or incorrect.')
            except:
                attempts += 1

        if attempts == len(params):
            if '-port' in connectArgs:
                raise IxNetError('Unable to connect to {host}{port}. Error: Host is unreachable'.format(host=hostname,
                       port= ':{0}'.format(connectArgs['-port'])))
            else:
                raise IxNetError('Unable to connect to {host}{port}. Error: Host is unreachable'.format(host=hostname,
                       port= ' using default ports (8009 or 443)'))
        return url

    def _restGetRedirect(self, url, timeout):
        self._log('{0} {1}'.format('HEAD', url))

        response = requests.head(url, verify=self.VERIFY_CERT, allow_redirects=True, headers=self._headers, timeout=timeout)
        self._log('{code} {reason} {url}'.format(code=response.status_code, reason=response.reason, url=response.url))

        if str(response.status_code) == '401' or str(response.status_code) == '403':
            raise IxNetAuthenticationError()

        return response.url.split('?')[0].split('#')[0].strip('/')

    def _restSend(self, method, url, payload=None, fid=None, file_content=None , timeout=180):
        self._log('{0} {1}'.format(method, url))

        headers = self._headers.copy()

        if payload is not None:
            response = requests.request(method, url, data=json.dumps(payload), headers=headers, verify=self.VERIFY_CERT, timeout=timeout)
        elif fid is not None:
            headers['Content-Type'] = 'application/octet-stream'
            if method == 'POST':
                fid.seek(0, 0)
                response = requests.request(method, url, data=fid, stream=True, headers=headers, verify=self.VERIFY_CERT, timeout=timeout)
            else:
                response = requests.request(method, url, stream=True, headers=headers, verify=self.VERIFY_CERT, timeout=timeout)
        elif file_content is not None:
            headers['Content-Type'] = 'application/octet-stream'
            response = requests.request(method, url, data=json.dumps(file_content), headers=headers, verify=self.VERIFY_CERT, timeout=timeout)
        else:
            response = requests.request(method, url, headers=headers, verify=self.VERIFY_CERT, timeout=timeout)

        self._log('{code} {reason}'.format(code=response.status_code, reason=response.reason))

        if not str(response.status_code).startswith('2'):
            try:
                msg = response.json().get('error')
                if not msg:
                    if response.json().get('errors'):
                        msg = ','.join(response.json().get('errors'))
                    else:
                        msg = response.text
            except ValueError:
                msg = response.text
            if str(response.status_code) == '401' or str(response.status_code) == '403':
                raise IxNetAuthenticationError('{0}'.format(msg))
            else:
                raise IxNetError('{code} {reason}: {text}'.format(code=response.status_code, reason=response.reason, text=msg))

        if response.headers.get('Content-Type') is None or response.status_code == 204:
            return None
        elif response.headers['Content-Type'] == 'application/octet-stream' and fid is not None:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    fid.write(chunk)
            return None
        else:
            contentObject = response.json()
            if isinstance(contentObject, list):
                data_list = []
                for contentItem in contentObject:
                    data = lambda: None
                    data.__dict__ = contentItem
                    data_list.append(data)
                return data_list
            else:
                data = lambda: None
                data.__dict__ = contentObject
                return data

    def _isSessionAvailable(self, session, raiseError=False):
        session.__dict__ = self._getDetailedSessionInfo(session)
        if session.inUse:
                if raiseError:
                    raise Exception('The requested session is currently in use.')
                return False
        return True

    def _getDetailedSessionInfo(self, session, baseURL=None, port=None):
        if not baseURL:
            baseURL = self._connectionInfo['url']
            port = self._connectionInfo['port']
        sessionURL = '{url}/{id}'.format(url=baseURL, id=session.id)
        sessionIxNetworkURL = '{url}/ixnetwork'.format(url=sessionURL)
        ixnet = None
        if str(session.state).lower() == 'active':
            try:
                ixnet = self._restSend('GET', '{0}/globals/ixnet'.format(sessionIxNetworkURL),  timeout= 3)
            except:
                pass
        if ixnet is None:
            ixnet = lambda: None
            ixnet.__dict__ = {"isActive": False, "connectedClients": []}
        session_info = {
                'id': session.id,
                'port': port,
                'url': sessionIxNetworkURL,
                'sessionUrl': sessionURL,
                'applicationType': session.applicationType,
                'backendType': self._tryGetAttr(session, 'backendType', default='LinuxAPIServer'),
                'state': session.state.lower(),
                'subState': session.subState,
                'inUse': ixnet.isActive or (session.subState and session.subState.lower().startswith('in use')),
                'userName': session.userName,
                'connectedClients': ixnet.connectedClients,
                'createdOn': session.createdOn,
                'startedOn': self._tryGetAttr(session, 'startedOn', None),
                'currentTime': self._tryGetAttr(session, 'currentTime', None),
                'stoppedOn': self._tryGetAttr(session, 'stoppedOn', None)
                }
        return session_info

    def _getArgMap(self, default_args, *args):
        name = None
        for arg in args:
            if str(arg).startswith('-'):
                name = str(arg)
            elif name is not None:
                default_args[name] = str(arg)
                name = None
        return default_args

    def _waitForState(self, state, url, timeout=450):
        timeout = int(timeout)
        sessionState = None
        startTime = int(time.time())
        while int(time.time() - startTime) < timeout:
            try:
                sessionState = self._restSend('GET', url).state.lower()
            except:
                self._log(sys.exc_info()[1])
                raise

            if sessionState == state or (state == 'stopped' and sessionState in ['initial', 'abnormallystopped']):
                return
            elif (state == 'active' and sessionState in ['stopped', 'stopping', 'abnormallystopped']) or (state == 'stopped' and sessionState in ['starting', 'active']):
                raise IxNetError('Session {id} was expected to reach state {state}. It reached the invalid state {invalidState}.'.format(id=self._connectionInfo['sessionId'], state=state, invalidState=sessionState))

            time.sleep(1.5)

        raise Exception('Session {id} did not reach state {state} with the time limit ({timeout} seconds).'.format(id=self._connectionInfo['sessionId'], state=state, timeout=timeout))


    def _cleanUpSession(self, url):
        try:
            self._restSend('POST', '{url}/{action}'.format(url=url, action='operations/stop'))
            self._waitForState('stopped', url)
        except:
            pass
        self._deleteSession(url)

    def _deleteSession(self, url):
        try:
            self._restSend('DELETE', url)
        except:
            pass


    def _checkObjRef(self, objRef):
        if not (type(objRef) in (str, unicode)):
            raise IxNetError('The objRef parameter must be ' + str(str) + ' instead of ' + str(type(objRef)))
        else:
            return objRef

    def _putFileOnServer(self, filename):
        basename = os.path.basename(filename.replace("\\","/"))
        files = self._restSend('GET', '{0}/ixnetwork/files'.format(self._connectionInfo['sessionUrl']))
        remote_filename = '{0}/{1}'.format(files.absolute.replace("\\","/"), basename)
        fid = None
        try:
            fid = io.open(filename, 'rb')
            self._restSend('POST', '{0}/ixnetwork/files?filename={1}'.format(self._connectionInfo['sessionUrl'],quote(basename)), fid=fid)
        finally:
            if fid is not None:
                fid.close()
        return self._sendRecv('ixNet', 'readFrom', remote_filename, '-ixNetRelative')

    def _createFileOnServer(self, filename):
        basename = os.path.basename(filename.replace("\\","/"))
        files = self._restSend('GET', '{0}/ixnetwork/files'.format(self._connectionInfo['sessionUrl']))
        remote_filename = '{0}/{1}'.format(files.absolute.replace("\\","/"), basename)
        self._restSend('POST', '{0}/ixnetwork/files?filename={1}'.format(self._connectionInfo['sessionUrl'], quote(basename)), file_content={})
        return self._sendRecv('ixNet', 'writeTo', remote_filename, '-ixNetRelative', '-overwrite', '-remote', filename)

    def _close(self):
        try:
            if self._websocket is not None:
                self._websocket.close()
        except:
            pass

        self._websocket = None

    def _join(self, *args):
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
                        self._join(item)
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
                    self._sendContent.append('{' + arg + '}')
                else:
                    self._sendContent.append(arg)

        return

    def _sendRecv(self, *args):
        self._isConnected(raiseError=True)
        self._addContentSeparator = 0
        self._firstItem = True

        argList = list(args)

        if self._async:
            argList.insert(1, '-async')

        if self._timeout is not None:
            argList.insert(1, '-timeout')
            argList.insert(2, self._timeout)

        for item in argList:
            self._join(item)

        self._sendContent.append('\03')
        self._sendBuffer.append(''.join(self._sendContent))
        if self._buffer is False:
            buffer = ''.join(self._sendBuffer)
            self._log(' '.join(('Sending:', buffer)))
            self._send('<001><002><009{0}>{1}'.format(len(buffer), buffer))
            self._sendBuffer = list()

        self._async = False
        self._timeout = None
        self._buffer = False
        self._sendContent = list()

        if len(self._sendBuffer) > 0:
            return self.OK
        else:
            return self._recv()

    def _send(self, content):
        try:
            if type(content) is str:
                content = content.encode('ascii')
            self._websocket.send(content)
        except (Exception):
            e = sys.exc_info()[1]
            self._close()
            raise IxNetError('Connection to the remote IxNetwork instance has been closed:' + str(e))

    def _recv(self):
        self._decoratedResult = list()
        responseBuffer = str()
        try:
            responseBuffer = self._websocket.recv().decode('ascii')
        except:
            e = sys.exc_info()[1]
            self._close()
            raise IxNetError('Connection to the remote IxNetwork instance has been closed:' + str(e))
        try:
            commandId = None
            contentLength = int(0)
            while len(responseBuffer) > 0:
                startIndex = int(responseBuffer.find('<'))
                stopIndex = int(responseBuffer.find('>'))
                if startIndex != -1 and stopIndex != -1:
                    commandId = int(responseBuffer[startIndex + 1 : startIndex + 4])
                    if startIndex + 4 < stopIndex:
                        contentLength = int(responseBuffer[startIndex + 4 : stopIndex])
                stopIndex += 1
                if commandId == 1:
                    self._evalResult = self._evalError
                elif commandId == 4:
                    self._evalResult = responseBuffer[stopIndex : stopIndex + contentLength]
                elif commandId == 7:
                    filename = responseBuffer[stopIndex : stopIndex + contentLength]
                    remoteFilename = os.path.basename(filename.replace("\\","/"))
                    if not os.path.exists(os.path.dirname(filename)):
                        os.makedirs(os.path.dirname(filename))

                    fid = None
                    try: 
                        fid = open(filename, "wb")
                        file_url = '{session_url}/ixnetwork/files?filename={filename}'.format(session_url=self._connectionInfo['sessionUrl'], filename=quote(remoteFilename))
                        self._restSend('GET', file_url, fid=fid)
                    finally:
                        if fid is not None:
                            fid.close()
                elif commandId == 9:
                    self._decoratedResult = responseBuffer[stopIndex : stopIndex + contentLength]
                responseBuffer = responseBuffer[stopIndex + contentLength :]
        except:
            e = sys.exc_info()[1]
            raise IxNetError(self._formatAsIxNetError(str(e)))
        self._log(' '.join(['Received:', ''.join(self._decoratedResult)]))

        if self._evalResult == self._evalError:
            raise IxNetError(''.join(self._decoratedResult))

        if len(self._decoratedResult) > 0 and self._decoratedResult[0].startswith('\01'):
            return eval(''.join(self._decoratedResult[1:]))
        else:
            return ''.join(self._decoratedResult)

    def _checkClientVersion(self):
        version = self.getVersion()
        if self._version != version:
            print('WARNING: IxNetwork Python library version {0} does not match the IxNetwork server version {1}'.format(self._version, version))

    def _isConnected(self, raiseError=False):
        if self._websocket is None:
            if raiseError is True:
                raise IxNetError('not connected')
            else:
                return False
        else:
            return True

    def _parseAsBool(self, val):
        if val is None:
           return False
        if isinstance(val, bool):
            return val
        if isinstance(val, int):
            return val != 0
        if isinstance(val, str):
            return val.strip().lower() != 'false' and \
                val.strip() != '0' and val.strip() != ''
        return True

    def _log(self, msg):
        if self._debug:
            dt = datetime.now().strftime("%a %b %d %X %Y")
            if (len(msg) > 1024):
                msg = ''.join([msg[:1024], '...'])
            print('[{timestamp}] [IxNet] [debug] {msg}'.format(timestamp=dt, msg=msg))

    def _tryGetAttr(self, obj, attr, default=None):
        try:
            return getattr(obj, attr)
        except AttributeError:
            return default
