# -*- coding: cp1252 -*-
################################################################################
#                                                                              #
#    Copyright 1997 - 2019 by IXIA  Keysight                                   #
#    All Rights Reserved.                                                      #
#                                                                              #
################################################################################

################################################################################
#                                                                              #
#                                LEGAL  NOTICE:                                #
#                                ==============                                #
# The following code and documentation (hereinafter "the script") is an        #
# example script for demonstration purposes only.                              #
# The script is not a standard commercial product offered by Ixia and have     #
# been developed and is being provided for use only as indicated herein. The   #
# script [and all modifications enhancements and updates thereto (whether      #
# made by Ixia and/or by the user and/or by a third party)] shall at all times #
# remain the property of Ixia.                                                 #
#                                                                              #
# Ixia does not warrant (i) that the functions contained in the script will    #
# meet the users requirements or (ii) that the script will be without          #
# omissions or error-free.                                                     #
# THE SCRIPT IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND AND IXIA         #
# DISCLAIMS ALL WARRANTIES EXPRESS IMPLIED STATUTORY OR OTHERWISE              #
# INCLUDING BUT NOT LIMITED TO ANY WARRANTY OF MERCHANTABILITY AND FITNESS FOR #
# A PARTICULAR PURPOSE OR OF NON-INFRINGEMENT.                                 #
# THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SCRIPT  IS WITH THE #
# USER.                                                                        #
# IN NO EVENT SHALL IXIA BE LIABLE FOR ANY DAMAGES RESULTING FROM OR ARISING   #
# OUT OF THE USE OF OR THE INABILITY TO USE THE SCRIPT OR ANY PART THEREOF     #
# INCLUDING BUT NOT LIMITED TO ANY LOST PROFITS LOST BUSINESS LOST OR          #
# DAMAGED DATA OR SOFTWARE OR ANY INDIRECT INCIDENTAL PUNITIVE OR              #
# CONSEQUENTIAL DAMAGES EVEN IF IXIA HAS BEEN ADVISED OF THE POSSIBILITY OF    #
# SUCH DAMAGES IN ADVANCE.                                                     #
# Ixia will not be required to provide any software maintenance or support     #
# services of any kind (e.g. any error corrections) in connection with the     #
# script or any part thereof. The user acknowledges that although Ixia may     #
# from time to time and in its sole discretion provide maintenance or support  #
# services for the script any such services are subject to the warranty and    #
# damages limitations set forth herein and will not obligate Ixia to provide   #
# any additional maintenance or support services.                              #
#                                                                              #
################################################################################

################################################################################
#                                                                              #
# Description:                                                                 #
#    This script intends to demonstrate how to use NGPF PCEP API.              #
#      1. Configures a PCE on the topology1 and a PCC on topology2. SRv6 PCE   #
#         capability is enabled in PCC and PCE .The PCE has one SRv6           #
#         PCEinitiated LSP with two ERO in it. The PCC has one PreEstablished  #
#		  LSP with one ERO in it.                                              #
#      2. Start PCC and PCE.                                                   #
#      3. Verify statistics from "Protocols Summary" view                      #
#      4. Fetch PCC SRv6 Detailed learned information                          #
#      5. Fetch PCE SRv6 Detailed learned information                          #
#      6. Send PCupdate over PreEstablished LSP(Modify ERO).                   #
#      7. Send PCupdate over PCEInitiated LSP(Modify ERO).                     #
#      8. Stop all protocols.                                                  # 
################################################################################
import os
import sys
import time

def assignPorts (ixNet, realPort1, realPort2) :
     chassis1 = realPort1[0]
     chassis2 = realPort2[0]
     card1    = realPort1[1]
     card2    = realPort2[1]
     port1    = realPort1[2]
     port2    = realPort2[2]

     root = ixNet.getRoot()
     vport1 = ixNet.add(root, 'vport')
     ixNet.commit()
     vport1 = ixNet.remapIds(vport1)[0]

     vport2 = ixNet.add(root, 'vport')
     ixNet.commit()
     vport2 = ixNet.remapIds(vport2)[0]

     chassisObj1 = ixNet.add(root + '/availableHardware', 'chassis')
     ixNet.setAttribute(chassisObj1, '-hostname', chassis1)
     ixNet.commit()
     chassisObj1 = ixNet.remapIds(chassisObj1)[0]

     if (chassis1 != chassis2) :
         chassisObj2 = ixNet.add(root + '/availableHardware', 'chassis')
         ixNet.setAttribute(chassisObj2, '-hostname', chassis2)
         ixNet.commit()
         chassisObj2 = ixNet.remapIds(chassisObj2)[0]
     else :
         chassisObj2 = chassisObj1
     # end if

     cardPortRef1 = chassisObj1 + '/card:%s/port:%s' % (card1,port1)
     ixNet.setMultiAttribute(vport1, '-connectedTo', cardPortRef1,
         '-rxMode', 'captureAndMeasure', '-name', 'Ethernet - 001')
     ixNet.commit()

     cardPortRef2 = chassisObj2 + '/card:%s/port:%s' % (card2,port2)
     ixNet.setMultiAttribute(vport2, '-connectedTo', cardPortRef2,
         '-rxMode', 'captureAndMeasure', '-name', 'Ethernet - 002')
     ixNet.commit()
# end def assignPorts

################################################################################
# Either feed the ixNetwork library path in the sys.path as below, or put the  #
# IxNetwork.py file somewhere else where we python can autoload it             #
# "IxNetwork.py" is available in <IxNetwork_installer_path>\API\Python         #
################################################################################
IX_NETWORK_LIBRARY_PATH = 'C:/Program Files (x86)/Ixia/IxNetwork/9.00.0.214-EB/API/Python'
sys.path.append(IX_NETWORK_LIBRARY_PATH)
import IxNetwork

#################################################################################
# Give chassis/client/ixNetwork server port/ chassis port HW port information   #
# below                                                                         #
#################################################################################
ixTclServer = '10.39.50.102'
ixTclPort   = '5556'
ports       = [('10.39.50.96', '10', '17',), ('10.39.50.96', '10', '19',)]

# get IxNet class
ixNet = IxNetwork.IxNet()
print("connecting to IxNetwork client")
ixNet.connect(ixTclServer, '-port', ixTclPort, '-version', '9.00',
     '-setAttribute', 'strict')

# cleaning up the old configfile, and creating an empty config
print("cleaning up the old configfile, and creating an empty config")
ixNet.execute('newConfig')

# assigning ports
assignPorts(ixNet, ports[0], ports[1])
time.sleep(5)

root    = ixNet.getRoot()
vportTx = ixNet.getList(root, 'vport')[0]
vportRx = ixNet.getList(root, 'vport')[1]

################################################################################
# 1. Configure the PCC and PCE as per the description given above.             #
################################################################################
print("adding topologies")
ixNet.add(root, 'topology', '-vports', vportTx)
ixNet.add(root, 'topology', '-vports', vportRx)
ixNet.commit()

topologies = ixNet.getList(ixNet.getRoot(), 'topology')
topo1 = topologies[0]
topo2 = topologies[1]

print ("Adding 2 device groups")
ixNet.add(topo1, 'deviceGroup')
ixNet.add(topo2, 'deviceGroup')
ixNet.commit()

t1devices = ixNet.getList(topo1, 'deviceGroup')
t2devices = ixNet.getList(topo2, 'deviceGroup')

t1dev1 = t1devices[0]
t2dev1 = t2devices[0]

print("Configuring the multipliers (number of sessions)")
ixNet.setAttribute(t1dev1, '-multiplier', '1')
ixNet.setAttribute(t2dev1, '-multiplier', '1')
ixNet.commit()

print("Adding ethernet/mac endpoints")
ixNet.add(t1dev1, 'ethernet')
ixNet.add(t2dev1, 'ethernet')
ixNet.commit()

mac1 = ixNet.getList(t1dev1, 'ethernet')[0]
mac2 = ixNet.getList(t2dev1, 'ethernet')[0]

print("Configuring the mac addresses %s" % (mac1))
ixNet.setAttribute(ixNet.getAttribute(mac1, '-mac') + '/singleValue',
    '-value', '18:03:73:C7:6C:B1')
ixNet.commit()

ixNet.setAttribute(ixNet.getAttribute(mac2, '-mac') + '/singleValue',
    '-value', '18:03:73:C7:6C:01')
ixNet.commit()

print ('ixNet.help(\'::ixNet::OBJ-/topology/deviceGroup/ethernet\')')
print (ixNet.help('::ixNet::OBJ-/topology/deviceGroup/ethernet'))

print("Add ipv4")
ixNet.add(mac1, 'ipv4')
ixNet.add(mac2, 'ipv4')
ixNet.commit()

ip1 = ixNet.getList(mac1, 'ipv4')[0]
ip2 = ixNet.getList(mac2, 'ipv4')[0]

mvAdd1 = ixNet.getAttribute(ip1, '-address')
mvAdd2 = ixNet.getAttribute(ip2, '-address')
mvGw1  = ixNet.getAttribute(ip1, '-gatewayIp')
mvGw2  = ixNet.getAttribute(ip2, '-gatewayIp')

print("configuring ipv4 addresses")
ixNet.setAttribute(mvAdd1 + '/singleValue', '-value', '20.20.20.2')
ixNet.setAttribute(mvAdd2 + '/singleValue', '-value', '20.20.20.1')
ixNet.setAttribute(mvGw1  + '/singleValue', '-value', '20.20.20.1')
ixNet.setAttribute(mvGw2  + '/singleValue', '-value', '20.20.20.2')

ixNet.setAttribute(ixNet.getAttribute(ip1, '-prefix') + '/singleValue', '-value', '24')
ixNet.setAttribute(ixNet.getAttribute(ip2, '-prefix') + '/singleValue', '-value', '24')

ixNet.setMultiAttribute(ixNet.getAttribute(ip1, '-resolveGateway') + '/singleValue', '-value', 'true')
ixNet.setMultiAttribute(ixNet.getAttribute(ip2, '-resolveGateway') + '/singleValue', '-value', 'true')
ixNet.commit()

print("Adding a PCC object on the Topology 2")
pce = ixNet.add(ip1, 'pce')
ixNet.commit()
pce = ixNet.remapIds(pce)[0]

print("Adding a PCC group on the top of PCE")
pccGroup = ixNet.add(pce, 'pccGroup')
ixNet.commit()
pccGroup = ixNet.remapIds(pccGroup)[0]

# Adding PCC with PreEstablished LSP 1
print("Adding a PCC object on the Topology 2")
pcc  = ixNet.add(ip2, 'pcc')
ixNet.commit()
pcc = ixNet.remapIds(pcc)[0]

# Add PreEstablished LSP
ixNet.setAttribute(pcc, '-preEstablishedSrLspsPerPcc',  '1')

# Set pcc group multiplier to 1
ixNet.setAttribute(pccGroup, '-multiplier',  '1')
ixNet.commit()

# Set PCC group's  "PCC IPv4 Address" field  to 20.20.20.1
pccIpv4AddressMv = ixNet.getAttribute(pccGroup, '-pccIpv4Address')
ixNet.setAttribute(pccIpv4AddressMv + '/singleValue', '-value',  '20.20.20.1')
ixNet.commit()

################################################################################
#Set SRv6 PCE capability in PCC and PCE                                        # 
# 1. SRv6 PCE capability                                                       #
# 2. Max Segments Left                                                         #
################################################################################
# set SRv6 capability in PCC
srv6pcccapabilityMv = ixNet.getAttribute(pcc, '-srv6PceCapability')
ixNet.setAttribute(srv6pcccapabilityMv + '/singleValue', '-value', 'True')
ixNet.commit()

#set max segment left
srv6maxslMv = ixNet.getAttribute(pcc, '-srv6MaxSL')
ixNet.setAttribute(srv6maxslMv + '/singleValue', '-value', '5')
ixNet.commit()

#Set SRv6 capability in PCE
srv6pcecapabilityMv = ixNet.getAttribute(pccGroup, '-srv6PceCapability')
ixNet.setAttribute(srv6pcecapabilityMv + '/singleValue', '-value', 'True')
ixNet.commit()

################################################################################
# Adding Pre-Established SRv6 LSPs                                             #
# Configured parameters :                                                      #
#    -initialDelegation                                                        #
#    -includeBandwidth                                                         #
#    -includeLspa                                                              #
#    -includeMetric                                                            # 
################################################################################
preEstdLsp = pcc+'/preEstablishedSrLsps:1'
initialDelegationMv = ixNet.getAttribute(preEstdLsp, '-initialDelegation')
ixNet.add(initialDelegationMv, 'singleValue')
ixNet.setMultiAttribute(initialDelegationMv + '/singleValue',
            '-value', 'true')
ixNet.commit()
includeBandwidthMv = ixNet.getAttribute(preEstdLsp, '-includeBandwidth')
ixNet.add(includeBandwidthMv, 'singleValue')
ixNet.setMultiAttribute(includeBandwidthMv + '/singleValue',
            '-value', 'true')
ixNet.commit()
includeLspaMv = ixNet.getAttribute(preEstdLsp, '-includeLspa')
ixNet.add(includeLspaMv, 'singleValue')
ixNet.setMultiAttribute(includeLspaMv + '/singleValue',
            '-value', 'true')
ixNet.commit()
includeMetricMv = ixNet.getAttribute(preEstdLsp, '-includeMetric')
ixNet.add(includeMetricMv, 'singleValue')
ixNet.setMultiAttribute(includeMetricMv + '/singleValue',
            '-value', 'true')
ixNet.commit()

################################################################################
# Set the properties SRv6 ERO in Preestablished LSP                            #
# a. Active                                                                    # 
# b. SRv6 NAI Type                                                             #
# c. F bit                                                                     #
# d. SRv6 Identifier                                                           #
# e. SRv6 Function Code                                                        #
# f. Local IPv6 Address                                                        #
# g. Remote IPv6 Address                                                       #
################################################################################
ero1activeMV = ixNet.getAttribute(
    pcc + '/preEstablishedSrLsps/pcepEroSubObjectsList:1',
    '-active')
ixNet.add(ero1activeMV, 'singleValue')
ixNet.setAttribute(ero1activeMV + '/singleValue', '-value',  'True')

ero1NaiTypeMv = ixNet.getAttribute(
    pcc + '/preEstablishedSrLsps/pcepEroSubObjectsList:1',
    '-srv6NaiType')
ixNet.setAttribute(ero1NaiTypeMv + '/singleValue', '-value',  'ipv6adjacency')

ero1FbitMv = ixNet.getAttribute(
    pcc + '/preEstablishedSrLsps/pcepEroSubObjectsList:1',
    '-fBit')
ixNet.setAttribute(ero1FbitMv + '/singleValue', '-value',  'False')

ero1SRv6IdentifierMv = ixNet.getAttribute(
    pcc + '/preEstablishedSrLsps/pcepEroSubObjectsList:1',
    '-srv6Identifier')
ixNet.setAttribute(ero1SRv6IdentifierMv + '/singleValue', '-value',  '2122::1')

ero1SRv6FunCodeMv = ixNet.getAttribute(
    pcc + '/preEstablishedSrLsps/pcepEroSubObjectsList:1',
    '-srv6FunctionCode')
ixNet.setAttribute(ero1SRv6FunCodeMv + '/singleValue', '-value',  'endfunction')

localIPv6AddressMv = ixNet.getAttribute(
    pcc + '/preEstablishedSrLsps/pcepEroSubObjectsList:1',
    '-localIpv6Address')
ixNet.setAttribute(localIPv6AddressMv + '/singleValue', '-value',  '2122::2')

remoteIPv6AddressMv = ixNet.getAttribute(
    pcc + '/preEstablishedSrLsps/pcepEroSubObjectsList:1',
    '-remoteIpv6Address')
ixNet.setAttribute(remoteIPv6AddressMv + '/singleValue', '-value',  '2122::3')

ixNet.commit()

################################################################################
#Set  pceInitiateLSPParameters                                                 # 
#Path Setup Type -- SRv6                                                       #
################################################################################
pathsetuptype = ixNet.getAttribute(
    pccGroup + '/pceInitiateLSPParameters' , '-pathSetupType')
ixNet.setAttribute(pathsetuptype + '/singleValue', '-value',  'srv6')

ixNet.commit()

################################################################################
# Set  pceInitiateLSPParameters                                                #
# 1. IP version                -- ipv6                                         #
# 2. IPv6 source endpoint      -- 2244::101                                    #
# 3. IPv6 destination endpoint -- 2344::101                                    #
################################################################################
ipVerisionMv = ixNet.getAttribute(pccGroup + '/pceInitiateLSPParameters',
    '-ipVersion')
ixNet.setAttribute(ipVerisionMv + '/singleValue', '-value', 'ipv6')
ixNet.commit()

Ipv6SrcEndpointsMv = ixNet.getAttribute(pccGroup + '/pceInitiateLSPParameters',
    '-srcEndPointIpv6')
ixNet.setAttribute(Ipv6SrcEndpointsMv + '/singleValue', '-value', '2244::101')

Ipv6DestEndpointsMv = ixNet.getAttribute(pccGroup + '/pceInitiateLSPParameters',
    '-destEndPointIpv6')
ixNet.setAttribute(Ipv6DestEndpointsMv + '/singleValue', '-value', '2344::101')
ixNet.commit()

# Set  pceInitiateLSPParameters
# 1. Include srp
Ipv4SrpEndpointsMv = ixNet.getAttribute(pccGroup + '/pceInitiateLSPParameters',
    '-includeSrp')
ixNet.setAttribute(Ipv4SrpEndpointsMv + '/singleValue',  '-value',  'True')
ixNet.commit()

################################################################################
# Set  pceInitiateLSPParameters                                                #
# a. Include srp                                                               #
# b. Include symbolic pathname TLV                                             #
# c. Symbolic path name                                                        #
# d. includeAssociation				                               #
# e. Include Bandwidth                                                         #
################################################################################
pceInitiateLSPParameters1 = pccGroup + '/pceInitiateLSPParameters:1'
includeLspMv = ixNet.getAttribute(pccGroup + '/pceInitiateLSPParameters',
    '-includeLsp')
ixNet.setAttribute(includeLspMv + '/singleValue', '-value', 'True')

includeSymbolicPathMv = ixNet.getAttribute(pccGroup + '/pceInitiateLSPParameters',
    '-includeSymbolicPathNameTlv')
ixNet.setAttribute(includeSymbolicPathMv + '/singleValue', '-value', 'True')    
    
symbolicPathNameMv = ixNet.getAttribute(pccGroup + '/pceInitiateLSPParameters',
    '-symbolicPathName')
ixNet.setAttribute(symbolicPathNameMv + '/singleValue', '-value',
    'IXIA_SAMPLE_LSP_1')
ixNet.commit()

# Add 2 EROs
ixNet.setMultiAttribute(pccGroup + '/pceInitiateLSPParameters',
    '-numberOfEroSubObjects', '2',
    '-name', '{Initiated LSP Parameters}')
ixNet.commit()

includeAssociationMv = ixNet.getAttribute(pceInitiateLSPParameters1, '-includeAssociation')
ixNet.add(includeAssociationMv, 'singleValue')
ixNet.setMultiAttribute(includeAssociationMv + '/singleValue',
            '-value', 'true')
ixNet.commit()

includebandwidthMv = ixNet.getAttribute(pceInitiateLSPParameters1, '-includeBandwidth')
ixNet.add(includebandwidthMv, 'singleValue')
ixNet.setMultiAttribute(includebandwidthMv + '/singleValue',
            '-value', 'true')
ixNet.commit()

################################################################################
# Set the properties of ERO1                                                   #
# a. Active                                                                    # 
# b. SRv6 NAI Type                                                             #
# c. F bit                                                                     #
# d. SRv6 Identifier                                                           #
# e. SRv6 Function Code                                                        #
################################################################################
ero1ActiveMv = ixNet.getAttribute(
    pccGroup + '/pceInitiateLSPParameters/pcepEroSubObjectsList:1',
    '-active')
ixNet.setAttribute(ero1ActiveMv + '/singleValue', '-value', 'True')

ero1NaiTypeMv = ixNet.getAttribute(
    pccGroup + '/pceInitiateLSPParameters/pcepEroSubObjectsList:1',
    '-srv6NaiType')
ixNet.setAttribute(ero1NaiTypeMv + '/singleValue', '-value', 'ipv6nodeid')

ero1IPv6NodeidMv = ixNet.getAttribute(
    pccGroup + '/pceInitiateLSPParameters/pcepEroSubObjectsList:1',
    '-ipv6NodeId')
ixNet.setAttribute(ero1IPv6NodeidMv + '/singleValue', '-value', '5556::1')

ero1FbitMv = ixNet.getAttribute(
    pccGroup + '/pceInitiateLSPParameters/pcepEroSubObjectsList:1',
    '-fBit')
ixNet.setAttribute(ero1FbitMv + '/singleValue', '-value', 'False')

ero1SRv6IdentifierMv = ixNet.getAttribute(
    pccGroup + '/pceInitiateLSPParameters/pcepEroSubObjectsList:1',
    '-srv6Identifier')
ixNet.setAttribute(ero1SRv6IdentifierMv + '/singleValue', '-value', '4445::1')

ero1SRv6FunCodeMv = ixNet.getAttribute(
    pccGroup + '/pceInitiateLSPParameters/pcepEroSubObjectsList:1',
    '-srv6FunctionCode')
ixNet.setAttribute(ero1SRv6FunCodeMv + '/singleValue', '-value', 'endfunction')

ixNet.commit()
################################################################################
# Set the properties of ERO2                                                   #
# a. Active                                                                    # 
# b. SRv6 NAI Type                                                             #
# c. F bit                                                                     #
# d. SRv6 Identifier                                                           #
# e. SRv6 Function Code                                                        #
################################################################################
ero2ActiveMv = ixNet.getAttribute(
    pccGroup + '/pceInitiateLSPParameters/pcepEroSubObjectsList:2',
    '-active')
ixNet.setAttribute(ero2ActiveMv + '/singleValue', '-value', 'True')

ero2NaiTypeMv = ixNet.getAttribute(
    pccGroup + '/pceInitiateLSPParameters/pcepEroSubObjectsList:2',
    '-srv6NaiType')
ixNet.setAttribute(ero2NaiTypeMv + '/singleValue', '-value', 'notapplicable')

ero2FbitMv = ixNet.getAttribute(
    pccGroup + '/pceInitiateLSPParameters/pcepEroSubObjectsList:2',
    '-fBit')
ixNet.setAttribute(ero2FbitMv + '/singleValue', '-value', 'False')

ero2SRv6IdentifierMv = ixNet.getAttribute(
    pccGroup + '/pceInitiateLSPParameters/pcepEroSubObjectsList:2',
    '-srv6Identifier')
ixNet.setAttribute(ero2SRv6IdentifierMv + '/singleValue', '-value', '4446::1')

ero2SRv6FunCodeMv = ixNet.getAttribute(
    pccGroup + '/pceInitiateLSPParameters/pcepEroSubObjectsList:2',
    '-srv6FunctionCode')
ixNet.setAttribute(ero2SRv6FunCodeMv + '/singleValue', '-value', 'enddx6function')

ixNet.commit()

# Set PCC's  "PCE IPv4 Address" field  to 20.20.20.20
pceIpv4AddressMv = ixNet.getAttribute(pcc, '-pceIpv4Address')
ixNet.setAttribute(pceIpv4AddressMv + '/singleValue', '-value', '20.20.20.2')
ixNet.commit()

################################################################################
# 2. Start PCEP protocol and wait for 45 seconds                               #
################################################################################
print("Starting protocols and waiting for 45 seconds for protocols to come up")
ixNet.execute('startAllProtocols')
time.sleep(45)

################################################################################
# 3. Retrieve protocol statistics                                              #
################################################################################
print ("Fetching all Protocol Summary Stats\n")
viewPage  = '::ixNet::OBJ-/statistics/view:"Protocols Summary"/page'
statcap   = ixNet.getAttribute(viewPage, '-columnCaptions')
for statValList in ixNet.getAttribute(viewPage, '-rowValues') :
    for  statVal in statValList :
        print("***************************************************")
        index = 0
        for satIndv in statVal :
            print("%-30s:%s" % (statcap[index], satIndv))
            index = index + 1
        # end for
    # end for
# end for
print("***************************************************")

################################################################################
# 4. Retrieve pcc SRv6 detailed learned info                                   #
################################################################################
totalNumberOfPcc = 1
i = 1
while (i <= totalNumberOfPcc) :
    ixNet.execute('getPccSrv6LearnedInfo', pcc, "%d"%i)
    i = i + 1
# end while

print('-' * 60)
learnedInfoList = ixNet.getList(pcc, 'learnedInfo')
for learnedInfo in learnedInfoList :
    table = ixNet.getList(learnedInfo, 'table')
    for t in table :
        colList = ixNet.getAttribute(t, '-columns')
        rowList = ixNet.getAttribute(t, '-values')
        for valList in rowList :
            ndx = 0  
            for val in valList :
                name  = colList[ndx]
                value = val
                print("%-30s:\t%s" % (name, value))
                ndx = ndx + 1
            # end for val in valList
            print('-' * 60)
        # end for valList in  $rowList
    # enf for t in table
# end for learnedInfo in learnedInfoList

################################################################################
# 5. Retrieve pce SRv6 detailed learned info                                   #
################################################################################
totalNumberOfPce = 1
i = 1
while (i <= totalNumberOfPce) :
    ixNet.execute('getPceDetailedAllSrv6LspLearnedInfo', pccGroup, "%d"%i)
    i = i + 1
# end while

print('-' * 60)
learnedInfoList = ixNet.getList(pcc, 'learnedInfo')
for learnedInfo in learnedInfoList :
    table = ixNet.getList(learnedInfo, 'table')
    for t in table :
        colList = ixNet.getAttribute(t, '-columns')
        rowList = ixNet.getAttribute(t, '-values')
        for valList in rowList :
            ndx = 0  
            for val in valList :
                name  = colList[ndx]
                value = val
                print("%-30s:\t%s" % (name, value))
                ndx = ndx + 1
            # end for val in valList
            print('-' * 60)
        # end for valList in  $rowList
    # enf for t in table
# end for learnedInfo in learnedInfoList
################################################################################
# 6. Change SRv6 Identifier ERO1 of PCinitiated LSP                            #
################################################################################
ixNet.setAttribute(ero1SRv6IdentifierMv + '/singleValue', '-value', 'abcd::1')
ixNet.commit()
ixNet.execute('applyOnTheFly', '/globals/topology')
time.sleep(5)

################################################################################
# 7. Change SRv6 Identifier ERO1 of PreEstablished LSP                         #
################################################################################
# Setting the TCL APIs for getting PCUpdate Triggers
learnedInfoUpdate = ixNet.getList(pccGroup, 'learnedInfoUpdate')[0]
trigger1 = learnedInfoUpdate+ '/pceDetailedSrv6SyncLspUpdateParams:1'
ero = ixNet.getAttribute(trigger1, '-configureEro')
ixNet.add(ero, 'singleValue')
ixNet.setMultiAttribute(ero + '/singleValue',
            '-value', 'modify')
ixNet.commit()
time.sleep(2)
ero1 = ixNet.getList(trigger1, 'pceUpdateSrv6EroSubObjectList')[0]
ero1SRv6IdentifierMv = ixNet.getAttribute(ero1, '-srv6Identifier')
ixNet.setAttribute(ero1SRv6IdentifierMv + '/singleValue', '-value', 'abcd::2')
ixNet.commit()
time.sleep(2)

print ("Send PCUpdate from Learned Info from PCE side")
ixNet.execute('sendPcUpdate', trigger1, 2)
time.sleep(5)
################################################################################
# 8. Stop all protocols                                                       #
################################################################################
print ('Stopping protocols')
ixNet.execute('stopAllProtocols')
print ('!!! Test Script Ends !!!')
