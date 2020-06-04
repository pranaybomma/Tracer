#!/bin/env python3
import sqlite3
import boto3
from os import system,path
import subprocess
from ipaddress import ip_address,ip_network


#IP,Subnet,SG,vpcid,ownerid,cidr
Src=[]
Dst=[]

#ec2 = boto3.resource('ec2','us-east-1')#location should be a choice
client = boto3.client('ec2','us-east-1')


def _filter(name,values):
    filter = {'Name': name, 'Values': [values]}
    return filter

def _Vpcs(ec2):
    _Account = {}
    for key,_vpcid in enumerate(ec2.vpcs.all()):
        '''Storing the VPC-ID and VPC-CIDR in the list along with enumeration in_Accont Dic
            Example_Account = {1:[vpc905438509, 192.168.0.0/24]}'''
        _NameOfVPC = [_name['Value'] for _name in _vpcid.tags if _name['Key']=='Name']
        if _NameOfVPC == []:#If thr tag is empty
            _NameOfVPC = ['Name-Not-Given']
            _Account[key+1]=[_vpcid.vpc_id, _vpcid.cidr_block,_NameOfVPC]
        else:
            _Account[key+1]=[_vpcid.vpc_id, _vpcid.cidr_block,_NameOfVPC]
    return _Account

def _Ec2s(vpcid,ec2):
    _Ec2 = {}
    InstanceId = ec2.instances.filter(Filters = [_filter('vpc-id',vpcid)])
    for _instances in InstanceId:
        if str(_instances.tags) != 'None':#To check if the tags exist
            '''Reading the tag values to gather name of the Instance
                if no name then it is marked as Name not given'''
            _NameOfInstance = [_name['Value'] for _name in _instances.tags if _name['Key']=='Name']
            if _NameOfInstance == []:
                _NameOfInstance = 'Name-Not-Given'
                _SecurityGroupId = [_sg['GroupId'] for _sg in _instances.security_groups ]
                _Ec2[int(len(_Ec2))+1] = [_NameOfInstance, _instances.private_ip_address, _instances.subnet_id, _SecurityGroupId ]
            else:
                _SecurityGroupId = [_sg['GroupId'] for _sg in _instances.security_groups ]
                _Ec2[int(len(_Ec2))+1] = [_NameOfInstance[0][0:40], _instances.private_ip_address, _instances.subnet_id, _SecurityGroupId ]
        else:
            ''' If no tags for the Instance '''
            _SecurityGroupId = [_sg['GroupId'] for _sg in _instances.security_groups ]
            _Ec2[int(len(_Ec2))+1] = ['Name Not Given', _instances.private_ip_address, _instances.subnet_id, _SecurityGroupId ]
    return _Ec2
def _SelectSrc(ec2):
    ''' Grepping Src IP,SubnetId,SG from first ACT'''
    system('clear')
    print('Total number of VPC\'s in ACT1 \n' + '-'*50)
    All_VPCs = _Vpcs(ec2)
    for key,value in All_VPCs.items():
        print(f"{str(key)}. {str(value[2][0]):25} {str(value[1]):20}")
    print()

    _Slct = int(input('select the vpc:'))
    print(f"{'Instances in:'}{All_VPCs[_Slct][0]}\n{'-'*130}")
    print(f"  {'Ec2-Name':40}{'IP':^30}{'Subnet-Id':^30}{'SG':40}\n{'-'*130}")
    All_Ec2s=_Ec2s(All_VPCs[_Slct][0],ec2)
    for key,value in All_Ec2s.items():
        print(f"{str(key)}.{str(value[0]):40}{str(value[1]):^30}{str(value[2]):^30} {str(value[3])}")
    print()

    _SlctSrc = int((input('select the Ec2:')))
    global Src
    Src=[All_Ec2s[_SlctSrc][1],All_Ec2s[_SlctSrc][2],All_Ec2s[_SlctSrc][3]]


def _SelectDst(ec2):

    ''' Grepping Src IP,SG from Second ACT'''
    system('clear')
    print('Total number of VPC\'s in ACT2 \n' + '-'*50)
    All_VPCs = _Vpcs(ec2)
    for key,value in All_VPCs.items():
        print(f"{str(key)}. {str(value[2][0]):25} {str(value[1]):20}")
    print()

    _Slct = int(input('select the vpc:'))
    print(f"{'Instances in:'}{All_VPCs[_Slct][0]}\n{'-'*130}")
    print(f"  {'Ec2-Name':40}{'IP':^30}{'Subnet-Id':^30}{'SG':40}\n{'-'*130}")
    All_Ec2s=_Ec2s(All_VPCs[_Slct][0],ec2)
    for key,value in All_Ec2s.items():
        print(f"{str(key)}.{str(value[0]):40}{str(value[1]):^30}{str(value[2]):^30} {str(value[3])}")
    print()

    _SlctDst = int((input('select the Ec2:')))
    global Dst
    Dst=[All_Ec2s[_SlctDst][1],All_Ec2s[_SlctDst][2],All_Ec2s[_SlctDst][3]]
    
def _SgEgress(Src,Dst,protocol,ec2):
    ''' Outobund Security Group Check
        _EgressCount is raised to 1 if one of the id matches
        then exists the loop'''
    _EgressCount = 0
    for IndividualSG in Src[2]:
        _SGrules = ec2.SecurityGroup(IndividualSG)
        _SGrules.load()
        for _IRules in _SGrules.ip_permissions_egress:
            if  _EgressCount == 1:
                break
            elif (protocol == _IRules['IpProtocol'].lower()) or (_IRules['IpProtocol'] == '-1'):#Need Additions with protocol and port
                if _IRules['UserIdGroupPairs']:
                    for _self in _IRules['UserIdGroupPairs']:
                        if ((_self['GroupId']) in Dst[2]):
                            _EgressCount += 1
                            print (f"\n{'SecurityGroup:'}{IndividualSG}\n{'-'*43}\n{'Egress SecurityGroup: Allowed using same SG'}\n{'-'*43}")

                else:
                    for _cidr in _IRules['IpRanges']:
                        if (ip_address(Dst[0]) in ip_network(_cidr['CidrIp'])):
                            _EgressCount += 1
                            print (f"\n{'SecurityGroup:'}{IndividualSG}\n{'-'*32}\n{'Egress SecurityGroup: Allowed'}\n{'-'*32}")

            else:
                print('No Outbound Access : Please check the Outbound Access on the Instance')
        if not _SGrules.ip_permissions_egress:
            print(f"\n{'No Security Group Rules found in '}{IndividualSG}")

def _SgIngress(Src,Dst,protocol,port,ec2):
    ''' Inbound Security Group Check
        _IngressCount is raised to 1 if one of the id matches
        then exists the loop'''
    _IngressCount = 0
    for IndividualSG in Dst[2]:
        _SGrules = ec2.SecurityGroup(IndividualSG)
        _SGrules.load()
        for _IRules in _SGrules.ip_permissions:
            if  _IngressCount == 1:
                break
            elif (protocol == _IRules['IpProtocol'].lower()) or (_IRules['IpProtocol'] == '-1'):
                if _IRules['IpRanges'] != []:
                    for _cidr in _IRules['IpRanges']:
                        if (ip_address(Src[0]) in ip_network(_cidr['CidrIp'])):
                            if 'FromPort' in _IRules:
                                if _IRules['FromPort'] != _IRules['ToPort']:
                                    if port in (range(_IRules['FromPort'],_IRules['ToPort']) or range(_IRules['ToPort'],_IRules['FromPort'])):
                                        _IngressCount += 1
                                        print (f"\n{'SecurityGroup:'}{IndividualSG}\n{'-'*32}\n{'Ingress SecurityGroup: Allowed'}\n{'-'*32}")
                                else:
                                    if (port == (_IRules['FromPort'])) or (port == (_IRules['ToPort'])):
                                        _IngressCount += 1
                                        print (f"\n{'SecurityGroup:'}{IndividualSG}\n{'-'*32}\n{'Ingress SecurityGroup: Allowed'}\n{'-'*32}")
                            else:
                                _IngressCount += 1
                                print (f"\n{'SecurityGroup:'}{IndividualSG}\n{'-'*32}\n{'Ingress SecurityGroup: Allowed'}\n{'-'*32}")
                        else:
                            continue

                elif _IRules['UserIdGroupPairs'] != []:
                    for _self in _IRules['UserIdGroupPairs']:
                        if ((_self['GroupId']) in Src[2]):
                            _IngressCount += 1
                            print (f"\n{'SecurityGroup:'}{IndividualSG}\n{'-'*32}\n{'Ingress SecurityGroup: Allowed using same SG'}\n{'-'*32}")
                else:
                    continue
            else:
                print('No Outbound Access : Please check the Inobund Access on the Instance')

        if not _SGrules.ip_permissions:
            print(f"\n{'No Security Group Rules found in '}{IndividualSG}")
#   if _IngressCount != 0:
#       print (f"\n{'SecurityGroup:'}\n{'-'*32}\n{'Ingress SecurityGroup: Allowed'}\n{'-'*32}")
#   else:
#       print (f"\n{'SecurityGroup:'}\n{'-'*32}\n{'Ingress SecurityGroup: NOTAllowed'}\n{'-'*32}")

def _SNetAcl(Src,Dst,protocol,port,ec2):
    ''' Network Acl check
         In              Out
         1024-65535     port
         Des            Des
         _InCount is raised to 1 when policy is matched in Ingress policy then skips the loop
         _Outount is raised to 1 when policy is matched in Outbound policy then skips the loop'''
    _InCount=0
    _OutCount=0

    for Acl in ec2.network_acls.filter(Filters = [_filter('association.subnet-id',Src[1])]):
        #for _NAcls in Acl.meta.data['Entries']:
        for _NAcls in Acl.entries:
            if _NAcls['Egress']==False:
                if _InCount == 1:
                    continue
                elif _NAcls['RuleAction']=='allow':
                    if (ip_address(Dst[0]) in ip_network(_NAcls['CidrBlock'])) and ((str(protocol) == _NAcls['Protocol']) or (_NAcls['Protocol'] == '-1')):
                        if 'PortRange' in _NAcls:
                            if _NAcls['PortRange']['From'] == 1024 and _NAcls['PortRange']['To']== 65535:
                                print(f"\n{'Ingress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'----'}{'Action:'}{_NAcls['RuleAction']}\n{'-'*32}{'Ephe'}")
                                _InCount += 1
                            else:
                                continue
                        else:
                            print(f"{'Ingress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'----'}{'Action:'}{_NAcls['RuleAction']}\n{'-'*32}")
                            _InCount += 1
                elif _NAcls['RuleAction']=='deny':
                    print(f"\n{'Ingress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'----'}{'Action:'}{_NAcls['RuleAction']}\n{'-'*32}")
                    _InCount += 1
                else:
                    print(f"\n{'Ingress NACL:'}\n{'-'*32}\n{'Action:'}{'Deny'}\n{'-'*32}")

            if _NAcls['Egress']==True:
                if _OutCount == 1:
                    continue
                elif _NAcls['RuleAction']=='allow':
                    if (ip_address(Dst[0]) in ip_network(_NAcls['CidrBlock'])) and ((str(protocol) == _NAcls['Protocol']) or (_NAcls['Protocol'] == '-1')):
                        if 'PortRange' in _NAcls:
                            if _NAcls['PortRange']['From'] != _NAcls['PortRange']['To']:
                                if port in range(_NAcls['PortRange']['From'],_NAcls['PortRange']['To']):
                                    print(f"{'Egress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'----'}{'Action:'}{_NAcls['RuleAction']}\n{'-'*32}")
                                    _OutCount += 1
                                else:
                                    continue
                            elif 'IcmpTypeCode' in _NAcls:
                                if ((str(protocol) == _NAcls['Protocol']) and (port == _NAcls['IcmpTypeCode']['Type'])):
                                    print(f"{'Egress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'----'}{'Action:'}{_NAcls['RuleAction']}\n{'-'*32}")
                                else:
                                    continue
                            else:
                                if (port ==_NAcls['PortRange']['From']) or (port==_NAcls['PortRange']['To']):
                                    print(f"{'Ingress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'----'}{'Action:'}{_NAcls['RuleAction']}\n{'-'*32}")
                                    _OutCount += 1
                                else:
                                    print(f"{'Ingress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'Deny due to ports'}\n{'-'*32}")
                                    _OutCount += 1

                        else:
                            print(f"{'Egress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'----'}{'Action:'}{_NAcls['RuleAction']}\n{'-'*32}")
                            _OutCount += 1
                elif _NAcls['RuleAction']=='deny':
                    print(f"{'Egress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'----'}{'Action:'}{_NAcls['RuleAction']}\n{'-'*32}")
                    _OutCount += 1
                else:
                    print(f"\n{'Egress NACL:'}\n{'-'*32}\n{'Action:'}{'Deny'}\n{'-'*32}")
                    
def _Route(Src,Dst,ec2):
    '''Route Table is evaluated by considering the subnet id of the selected Instance
        r is Incremented to 1 if the destination ip is in that given route list and marked as Our route '''
    Src.append(SrcEc2.Subnet(id=Src[1]).vpc_id)
    Dst.append(DstEc2.Subnet(id=Dst[1]).vpc_id)
    Src.append(SrcEc2.Vpc(id=Src[3]).owner_id)
    Dst.append(DstEc2.Vpc(id=Dst[3]).owner_id)
    Src.append(SrcEc2.Vpc(id=Src[3]).cidr_block)
    Dst.append(DstEc2.Vpc(id=Dst[3]).cidr_block)
    SVPC_CIDR=ip_network(Src[5])
    DVPC_CIDR=ip_network(Dst[5])
    r=0



    for routeTable in ec2.route_tables.filter(Filters = [_filter('association.subnet-id',Src[1])]):
        print(f"\n\n{'Route Table:'}{routeTable.id}\n{'-'*100}\n{'Destination':30}{'Target':^30} {'State':^30}\n {'-'*100}")
        for Attributes in routeTable.routes_attribute:
            Target=''
            if 'DestinationPrefixListId' in Attributes:#Skipping VPCe endpoints like s3
                continue
            if 'NetworkInterfaceId' in Attributes:
                Target = Attributes['NetworkInterfaceId']
            if 'TransitGatewayId' in Attributes:
                Target = Attributes['TransitGatewayId']
#           if 'GatewayId' in Attributes and Target!='':
#               Target = Target +'['+ Attributes['GatewayId']+']'
#           if  'GatewayId' in Attributes and Target=='':
            if  'GatewayId' in Attributes:
                Target = Attributes['GatewayId']
            if (ip_address(Dst[0]) in ip_network(Attributes['DestinationCidrBlock'])) and (r==0):
                print(f"{Attributes['DestinationCidrBlock']:30}{Target:^30}{Attributes['State']:^30} {'<---Our route'}")
                if 'tgw' in Target:
                    TgwCaught = True#if the target is TGWID it will go the TGW Tabble
                else:
                    TgwCaught = Target
                r+=1
            else:
                print(f"{Attributes['DestinationCidrBlock']:30}{Target:^30}{Attributes['State']:^30}")

    if (SVPC_CIDR.overlaps(DVPC_CIDR)) == True and (Src[3]!=Dst[3]):
        print(f"\n{'CIDR Overlaps... '}")
        exit()
    if TgwCaught==True:
        return routeTable.vpc_id
    elif 'local'== TgwCaught:
        print(f"{'Traffic is routed to '}{TgwCaught}\n")
    else:
        print(f"{'Traffic is routed to '}{TgwCaught}\n")
        exit()
def _STgw(vpc):
    Sroutematch=0
    Mroutematch=0
    match=''
    RouteTableid=''
    SRoutes=[]
    MRoutes=[]
    Sresponse = client.describe_transit_gateway_attachments(Filters = [_filter('resource-id',vpc)])
    for Attachments in Sresponse['TransitGatewayAttachments']:
#       print(Attachments['TransitGatewayAttachmentId'])
#       print(Attachments['Association']['TransitGatewayRouteTableId'])
        RouteTableid= Attachments['Association']['TransitGatewayRouteTableId']
#       print(Attachments['TransitGatewayOwnerId'])
        RouteTableState=Attachments['State']

    print(f"\n{'Routes on '}{RouteTableid}\n{'-'*100}\n{'CIDR':^30}{'ResourceId':^30}\n{'-'*100}")
    TgwRouteTable = client.search_transit_gateway_routes(
                                                        TransitGatewayRouteTableId=RouteTableid,
                                                        Filters=[_filter('state','active')])
    for cidr in TgwRouteTable['Routes']:
        SRoutes.append(cidr['DestinationCidrBlock'])
    for SortedCidr in sorted(SRoutes,key=lambda route: route.split("/")[1],reverse=True):
        if ip_address(Dst[0]) in ip_network(SortedCidr):
            for attbutes in TgwRouteTable['Routes']:
                if SortedCidr==attbutes['DestinationCidrBlock'] and Sroutematch==0:
                    for Tgwresource in attbutes['TransitGatewayAttachments']:
                        print(f"{attbutes['DestinationCidrBlock']:^30}{Tgwresource['ResourceId']:^30}{'    <--- Our Route'}")
                        Sroutematch+=1
                        if 'vpn' in Tgwresource['ResourceId']:
                            Resrc = Tgwresource['ResourceId'].split('(')[0]
                        elif Dst[3] == Tgwresource['ResourceId']:
                            match=1


    if 'vpn' in Resrc:
        Mresponse = client.describe_transit_gateway_attachments(Filters = [_filter('resource-id',Resrc)])
        for Attachment in Mresponse['TransitGatewayAttachments']:
            RouteTableid= Attachment['Association']['TransitGatewayRouteTableId']
        print(f"\n{'Routes on '}{RouteTableid}\n{'-'*100}\n{'CIDR':^30}{'ResourceId':^30}\n{'-'*100}")
        MTgwRouteTable = client.search_transit_gateway_routes(
                                                            TransitGatewayRouteTableId=RouteTableid,
                                                            Filters=[_filter('state','active')])
        for Mcidr in MTgwRouteTable['Routes']:
            MRoutes.append(Mcidr['DestinationCidrBlock'])

        for MSortedCidr in sorted(MRoutes,key=lambda route: route.split("/")[1],reverse=True):
            if ip_address(Dst[0]) in ip_network(MSortedCidr):
                for Mattbutes in MTgwRouteTable['Routes']:
                    if MSortedCidr==Mattbutes['DestinationCidrBlock'] and Mroutematch==0:
                        for MTgwresource in Mattbutes['TransitGatewayAttachments']:
                            print(f"{Mattbutes['DestinationCidrBlock']:^30}{MTgwresource['ResourceId']:^30}{'    <--- Our Route'}")
                            Mroutematch+=1
                            if 'vpn' in MTgwresource['ResourceId']:
                                match='Exiting'
                            elif Dst[3] == MTgwresource['ResourceId']:
                                match = 1
    if match == 1:
        print ('\nDestination VPC is ATTACHED to the TGW\n')
        return match
    else:
        print('\nDude clearly no clue where the route is going\n')
#        exit()


def _DNetAcl(Src,Dst,protocol,port,ec2):
    ''' Network Acl check
         In              Out
         port       1024-65535
         src            src
         _InCount is raised to 1 when policy is matched in Ingress policy then skips the loop
         _Outount is raised to 1 when policy is matched in Outbound policy then skips the loop'''
    _InCount=0
    _OutCount=0

    for Acl in ec2.network_acls.filter(Filters = [_filter('association.subnet-id',Dst[1])]):
        #for _NAcls in Acl.meta.data['Entries']:
        for _NAcls in Acl.entries:
            if _NAcls['Egress']==False:
                if _InCount == 1:
                    continue
                elif _NAcls['RuleAction']=='allow':
                    if (ip_address(Src[0]) in ip_network(_NAcls['CidrBlock'])) and ((str(protocol) == _NAcls['Protocol']) or (_NAcls['Protocol'] == '-1')):
                        if 'PortRange' in _NAcls:
                            if _NAcls['PortRange']['From'] != _NAcls['PortRange']['To']:
                                if port in (range(_NAcls['PortRange']['From'],_NAcls['PortRange']['To']) or range(_NAcls['PortRange']['To'],_NAcls['PortRange']['From'])):
                                    print(f"{'Ingress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'----'}{'Action:'}{_NAcls['RuleAction']}\n{'-'*32}")
                                    _InCount += 1
                                else:
                                    print(f"{'Ingress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'Deny due to ports'}\n{'-'*32}")
                                    _InCount += 1
                            else:
                                if (port ==_NAcls['PortRange']['From']) or (port==_NAcls['PortRange']['To']):
                                    print(f"{'Ingress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'----'}{'Action:'}{_NAcls['RuleAction']}\n{'-'*32}")
                                    _InCount += 1
                                else:
                                    print(f"{'Ingress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'Deny due to ports'}\n{'-'*32}")
                                    _InCount += 1

                        else:
                            print(f"{'Ingress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'----'}{'Action:'}{_NAcls['RuleAction']}\n{'-'*32}")
                            _InCount += 1
                    else:
                        print(f"{'Ingress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'----'}{'Action:'}{_NAcls['RuleAction']}\n{'-'*32}")
                        _InCount += 1

                elif _NAcls['RuleAction']=='deny':
                    print(f"{'Ingress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'----'}{'Action:'}{_NAcls['RuleAction']}\n{'-'*32}")
                    _InCount += 1

            if _NAcls['Egress']==True:
                if _OutCount == 1:
                    continue
                elif _NAcls['RuleAction']=='allow':
                    if (ip_address(Src[0]) in ip_network(_NAcls['CidrBlock'])) and ((str(protocol) == _NAcls['Protocol']) or (_NAcls['Protocol'] == '-1')):
                        if 'PortRange' in _NAcls:
                            if _NAcls['PortRange']['From'] == 1024 and _NAcls['PortRange']['To']== 65535:
                                print(f"\n{'Egress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'----'}{'Action:'}{_NAcls['RuleAction']}\n{'-'*32}{'Ephe'}")
                                _OutCount += 1
                            else:
                                continue
                        else:
                            print(f"{'Egress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'----'}{'Action:'}{_NAcls['RuleAction']}\n{'-'*32}")
                            _OutCount += 1
                elif _NAcls['RuleAction']=='deny':
                    print(f"\n{'Egress NACL:'}\n{'-'*32}\n{'RuleNumber:'}{_NAcls['RuleNumber']}{'----'}{'Action:'}{_NAcls['RuleAction']}\n{'-'*32}")
                    _OutCount += 1


def _Account(Act_Number):
    _MainAct = subprocess.getoutput('curl http://169.254.169.254/latest/dynamic/instance-identity/document')

    if str(Act_Number) in _MainAct:
        ec2 = boto3.resource('ec2','us-east-1')
        return (ec2)
    else:
        sts_client = boto3.client('sts')
        assumed_role_object=sts_client.assume_role(
            RoleArn="arn:aws:iam::"+str(Act_Number)+":role/FlightPath",
            RoleSessionName='Act'+str(Act_Number)
        )

        credentials=assumed_role_object['Credentials']
        ec2=boto3.resource(
        'ec2',
        region_name = 'us-east-1',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        )
        return (ec2)

def dbselect(c,accountName):
    table={}
    try:
        sqltable = "SELECT * from inventorydb"
        result = c.execute(sqltable)
        fulltable = c.fetchall()
        print(f"\n{'id'} {'Name':10}{'Number':^12}")
        for num,values in enumerate(fulltable):
            print(f"{num+1}. {values[0]:10}{values[1]:12}")
            table[num+1]=values
        ActNumselect=int(input(f"\nSelect the {accountName} ActNum:\n"))
        return(table[ActNumselect][1])

    except Exception as dbException:
        print('Could not access DB: ---> ', dbException)
def main():
    BASE_DIR = path.dirname(path.dirname(path.abspath(__file__)))
    db=path.join(BASE_DIR,"Database/inventorydb")
    connection = sqlite3.connect(db)
    c = connection.cursor()
    protocol = input('\nPlease Enter the Protocol: ').lower()
    if protocol == 'tcp':
        protocol_num = 6
    if protocol == 'udp':
        protocol_num = 17
    if protocol == 'icmp':
        protocol_num = 1
    port = int(input('\nPlease Enter the Port: '))
    global SrcEc2,DstEc2
    SrcEc2=_Account(dbselect(c,'Source'))
    DstEc2=_Account(dbselect(c,'Destination'))
    _SelectSrc(SrcEc2)
    _SelectDst(DstEc2)
    print(f"{'Provided Details'}\n{'-'*50}")
    print(f"{'SRC':^15}{'DST':^15}{'Protocol':^10}{'Port':^10}")
    print(f"{Src[0]:^15}{Dst[0]:^15}{protocol:^10}{port:^10}")
    if Src[0]!=Dst[0]:
        if SrcEc2.Subnet(Src[1]).vpc_id == DstEc2.Subnet(Dst[1]).vpc_id:
            if SrcEc2.Subnet(Src[1]) == DstEc2.Subnet(Dst[1]):
                _SgEgress(Src,Dst,protocol,SrcEc2)
                _SgIngress(Src,Dst,protocol,port,DstEc2)
                print()
                print('Src and Destination are located in same VPC and same SUBNET')
            else:
                _SgEgress(Src,Dst,protocol,SrcEc2)
                print()
                _SNetAcl(Src,Dst,protocol_num,port,SrcEc2)
                _Route(Src,Dst,SrcEc2)
                _DNetAcl(Src,Dst,protocol_num,port,DstEc2)
                _SgIngress(Src,Dst,protocol,port,DstEc2)
                print('Src and Destination are located in same VPC')
        else:
            _SgEgress(Src,Dst,protocol,SrcEc2)
            print()
            _SNetAcl(Src,Dst,protocol_num,port,SrcEc2)
            _STgw(_Route(Src,Dst,SrcEc2))
            _DNetAcl(Src,Dst,protocol_num,port,DstEc2)
            _SgIngress(Src,Dst,protocol,port,DstEc2)


    else:
        print('Source and Destination are IDENTICAL :)')


if __name__ == '__main__':
    main()
