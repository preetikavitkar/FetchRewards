# Fetch Rewards! - Exercise

import boto3
import yaml
import os
import time
import json

# Start reading input yaml file
with open(os.path.abspath("instances.yaml"), 'r') as yamlfile:
    in_file = yaml.full_load(yamlfile)

    servers = in_file['server']
    volumes = servers['volumes']
    users   = servers['users']

    for i in servers :
        print(i)
    for j in reversed(volumes) :
        for devices in j :
            print(devices)
    for k in users :
        for use_info in k :
            print(use_info)

# setting up env

res = boto3.resource('ec2')
ec2 = boto3.client('ec2')
iam = boto3.resource('iam')
iam1 = boto3.client('iam')
ssm_client = boto3.client('ssm')
send_key = boto3.client('ec2-instance-connect')

#create a key pair

key_pair=res.create_key_pair(KeyName="RewardsKey")
key_value=key_pair.key_material
#
with open(os.path.abspath("RewardsKey.pem"), 'w', encoding="utf-8") as keyfile :
    keyfile.write(str(key_value))
    keyfile.close()

# Create group, user and attach SSM role
#Create IAM instance profile, role and attach policy

policy= iam.Policy('arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM')

instance_profile = iam1.create_instance_profile(InstanceProfileName='Rewards')

assume_role_policy_document = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
        "Effect": "Allow",
        "Principal": {
            "Service": "ec2.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
        }
    ]
    })

#Create Role

create_role_response = iam1.create_role(
    RoleName = 'ec2ssm',
    AssumeRolePolicyDocument = assume_role_policy_document
    )

attach_add = iam1.add_role_to_instance_profile(
    InstanceProfileName='Rewards',
    RoleName='ec2ssm'
    )
#Attach policy 
attach_policy = iam1.attach_role_policy(
    RoleName='ec2ssm',
    PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM'
    )
 
#Create group, users 
   
group = iam.create_group(GroupName='GrpRewards')
use1  = iam.create_user(UserName='User1')
use2  = iam.create_user(UserName='User2')
user1 = group.add_user(UserName='User1')
user2 = group.add_user(UserName='User2')

attach_policy_group = policy.attach_group(GroupName='GrpRewards')
#

#Create a security group

res.create_security_group(Description="For Fetch rewards exercise", GroupName="Rewards-SG")

#Enable inbound rule for the security group
#
ec2.authorize_security_group_ingress(GroupName="Rewards-SG",
                                     IpPermissions=[
                                            {
                                                'FromPort' : 0,
                                                'IpProtocol' : '-1',
                                                'IpRanges' : [
                                                    {
                                                        'CidrIp' : '0.0.0.0/0'
                                                    },
                                                ],
                                                'ToPort' : 65536,
                                            }
                                        ]
                                        )

# Create an EC2 instance

time.sleep(60)
instance = ec2.run_instances(
    BlockDeviceMappings = [
        {
            'DeviceName': j['device'],
            'Ebs': {
                'VolumeSize': j['size_gb'],
                'VolumeType': 'standard'
            },
        },

    ],
    KeyName='RewardsKey',
    IamInstanceProfile={
           'Name' : 'Rewards'
       },
    SecurityGroups=["Rewards-SG"],
    ImageId=servers['ami_type'],
    InstanceType=(servers['instance_type']),
    MinCount=(servers['min_count']),
    MaxCount=(servers['max_count']),
    UserData="""
    #!/bin/bash
    mkdir /tmp/ssm
    cd /tmp/ssm
    wget https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
    sudo rpm --install amazon-ssm-agent.rpm
    sudo systemctl enable amazon-ssm-agent
    sudo systemctl start amazon-ssm-agent
    """
    )
#

instance_info =instance['Instances']

#insta_status = instance_stats['InstanceStatuses']
for stats in instance_info  :
    print(stats['Placement']['AvailabilityZone'])
    print(stats['State']['Name'])
    print(stats['InstanceId'])


if stats['State']['Name'] == 'pending' :

   vol2 = ec2.create_volume(AvailabilityZone=stats['Placement']['AvailabilityZone'],
                            Size=100,
                            VolumeType='gp2'
   )
#
#Attach volume
#
   if vol2['ResponseMetadata']['HTTPStatusCode'] == 200 :
      volume_id = vol2['VolumeId']
      print('***volume:', volume_id)
      ec2.get_waiter('volume_available').wait(
          VolumeIds=[volume_id])
      print('***Success!! volume:', volume_id, 'created...')
      time.sleep(120)
      attach_vol2 = ec2.attach_volume(
          Device='/dev/xvdf',
          InstanceId=stats['InstanceId'],
          VolumeId=vol2['VolumeId']
      )

      # use SSM RunCommand to format and mount volumes
      
      ssm = ssm_client.send_command(
          InstanceIds=[stats['InstanceId']],
          DocumentName='AWS-RunShellScript',
          Parameters={
              'commands': [
                  'echo "STARTING MOUNT SEQUENCE"'
                  'echo $(lsblk)'
                  'mkfs  -t xfs /dev/xvdh',
                  'mkdir /data',
                  'mount /dev/xvdh /data'
              ]
          }
      )

print("Congratulation! The instance has been created successfully : ", stats['InstanceId'])

#Connect/ssh to an instance
chmd_cmd = os.system('chmod 400 RewardsKey.pem')
pub_key = os.popen('ssh-keygen -y -f RewardsKey.pem').readlines()
public_key = pub_key[0]

for k in users:
    for use_info in k:

        if k[use_info] == 'user1' :
            connect_user1 = send_key.send_ssh_public_key(
                InstanceId=stats['InstanceId'],
                InstanceOSUser=k[use_info],
                SSHPublicKey=public_key,
                AvailabilityZone=stats['Placement']['AvailabilityZone']
            )
        elif k[use_info] == 'user2':
                connect_user2 = send_key.send_ssh_public_key(
                    InstanceId=stats['InstanceId'],
                    InstanceOSUser=(k[use_info]),
                    SSHPublicKey=public_key,
                    AvailabilityZone=(stats['Placement']['AvailabilityZone'])
                )

##******