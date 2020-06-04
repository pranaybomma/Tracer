#!/usr/bin/env python3
##Select the VPC and list all the available Instaces in that Specific VPC

import boto3
from os import system
import subprocess
system('clear')
Act_Name = input('Please Input the Account Name:')
Act_Number = input('Please Input the Account Num: [1.027354996282, 2.716405217398]:\n')

#Getting the Meta data from the instance
_MainAct = subprocess.getoutput('curl http://169.254.169.254/latest/dynamic/instance-identity/document')
_Account = {}



#Looking out for main Account
if Act_Number in _MainAct:
    ec2 = boto3.resource('ec2','us-east-1')
    for _vpcid in ec2.vpcs.all():
        #Storing the VPC-ID and VPC-CIDR in the list along with Int in_Accont Dic
        #Example_Account = {1:[vpc905438509, 192.168.0.0/24]}
        _Account[int(len(_Account))+1] = [_vpcid.vpc_id, _vpcid.cidr_block]
    for key,value in _Account.items():
        print()
        print('Total number of VPC\'s in '+ str(Act_Number))
        print('-'*80)
        print (str(key) +"."+str(value[0])+"--"+str(value[1]))
    print()

    _Slct = int((input('select the vpc:')))
    print()
    #filter the Instance with the selected VPC's
    filter = {'Name': 'vpc-id', 'Values': [_Account[_Slct][0]]}
    print (f"{'Ec2-Name':50}{'IP':^30}")
    print('-'*80)
    InstanceId = ec2.instances.filter(Filters = [filter])
    for i in InstanceId:
        if str(i.tags) != 'None':
            #Reading the tag Keys with Name
            _NameOfInstance = [_name['Value'] for _name in i.tags if _name['Key']=='Name']
            if _NameOfInstance == []:
                _NameOfInstance = ['Name-Not-Given']
                print(f"{'Name Not Given':50}{i.private_ip_address:^30}")
            else:
                print(f"{_NameOfInstance[0][0:40]:50}{i.private_ip_address:^30}")
        else:
            print(f"{'Name Not Given':50}{i.private_ip_address:^30}")

#considering Assume role if this is not the main Account
else:
    sts_client = boto3.client('sts')

    assumed_role_object=sts_client.assume_role(
#        RoleArn="arn:aws:iam::716405217398:role/FlightTest_role",
        RoleArn="arn:aws:iam::"+Act_Number+":role/FlightTest_role",
        RoleSessionName="AssumeRoleSession1"
    )

    credentials=assumed_role_object['Credentials']

    ec2=boto3.resource(

        'ec2',
        region_name = 'us-east-1',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
    )
########################################################################    
    for _vpcid in ec2.vpcs.all():
        #Storing the VPC-ID and VPC-CIDR in the list along with Int in_Accont Dic
        #Example_Account = {1:[vpc905438509, 192.168.0.0/24]}
        _Account[int(len(_Account))+1] = [_vpcid.vpc_id, _vpcid.cidr_block]
    for key,value in _Account.items():
        print()
        print('Total number of VPC\'s in '+ str(Act_Number))
        print('-'*80)
        print (str(key) +"."+str(value[0])+"--"+str(value[1]))
    print()
    _Slct = int((input('select the vpc:')))
    print()
    #filter the Instance with the selected VPC's
    filter = {'Name': 'vpc-id', 'Values': [_Account[_Slct][0]]}
    print (f"{'Ec2-Name':50}{'IP':^30}")
    print('-'*80)
    InstanceId = ec2.instances.filter(Filters = [filter])
    for i in InstanceId:
        if str(i.tags) != 'None':
            #Reading the tag Keys with Name
            _NameOfInstance = [_name['Value'] for _name in i.tags if _name['Key']=='Name']
            if _NameOfInstance == []:
                _NameOfInstance = ['Name-Not-Given']
                print(f"{'Name Not Given':50}{i.private_ip_address:^30}")
            else:
                print(f"{_NameOfInstance[0][0:40]:50}{i.private_ip_address:^30}")
        else:
            print(f"{'Name Not Given':50}{i.private_ip_address:^30}")
