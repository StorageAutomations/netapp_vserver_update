import requests
import base64
import json
from time import sleep
import boto3
from botocore.exceptions import ClientError
import logging
import cfnresponse
 
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def getClusterInformation(clusterAddress,username,password):
    #Dictionary to holder cluster information
    clusterDict = {}

    #Adding URL, usr, and password to the Cluster Dictionary
    clusterDict['url'] = 'https://'+clusterAddress
    AuthBase64String = base64.encodebytes(('%s:%s' % (username, password)).encode()).decode().replace('\n', '')
    clusterDict['header'] = {
        'authorization': "Basic %s" % AuthBase64String
    }

    #String for cluster api call
    clusterString = "/api/cluster"

    #Get Call for cluster information
    clusterNameReq = requests.get(clusterDict['url']+clusterString,
        headers=clusterDict['header'],
        verify=False)
    #catch clusterNameReq.status_code

    #Adding cluster's name to dictionary
    clusterDict['name'] = clusterNameReq.json()['name']

    #String for getting intercluster IP Addresses (Needs to be updated to limit to specific SVM)
    networkIntString = "/api/network/ip/interfaces?services=intercluster-core&fields=ip.address"

    #Get call for IP Addresses
    networkIntReq = requests.get(clusterDict['url']+networkIntString,
        headers=clusterDict['header'],
        verify=False)

    #Adding interfaces to an array in the dictionary
    clusterDict['interfaces'] = []
    for record in networkIntReq.json()['records']:
        clusterDict['interfaces'].append(record['ip']['address'])

    return clusterDict

def getSVMFromCluster(clusterDict, svmName = None):
    #Creating dictionary with an array of SVMs
    svmsDict = {"svms":[]}

    #Getting a list of SVMS
    svmsString = "/api/svm/svms?name=" + svmName
    svmReq = requests.get(clusterDict['url']+svmsString,
            headers=clusterDict['header'],
            verify=False)

    #Saving array of SVMs to the SVM Dictionary
    svmsDict = svmReq.json()['records']

    return svmsDict

def getSvmMaxTxSize(clusterDict, svmUuid):
    svmsString = "/api/protocols/nfs/services/{}?fields=transport.tcp_max_transfer_size".format(svmUuid)
    svmReq = requests.get(clusterDict['url']+svmsString,
            headers=clusterDict['header'],
            verify=False).json()['transport']

    #Saving array of SVMs to the SVM Dictionary
    return svmReq

def setSVMsdetails(clusterDict, svmUuid, payload):
    svmsString = "/api/protocols/nfs/services/{}".format(svmUuid)
    svmReq = requests.patch(clusterDict['url']+svmsString,
            headers=clusterDict['header'],
            verify=False,
            json=payload)

    #Saving array of SVMs to the SVM Dictionary
    return svmReq

def get_secret(secret_name, region_name):

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    # Decrypts secret using the associated KMS key.
    secret = json.loads(get_secret_value_response['SecretString'])
    
    return secret
    
# create AWS Lambda Function to setSVMdetails with provided payload
def lambda_handler(event, context):
    print(event)
    cParameters = (
        event['ResourceProperties']['fsxAddr'], 
        event['ResourceProperties']['fsxAdminUser'], 
        event['ResourceProperties']['fsxPassword'],
        event['ResourceProperties']['svmName'],
        event['ResourceProperties']['tcp_max_transfer_size']
    )
    
    fsxPassword = get_secret(cParameters[2], 'us-west-2')['fsxadmin']
    
    BASE64STRING = base64.encodebytes(
            ('%s:%s' %
                (cParameters[1],
                fsxPassword)
            ).encode()
        ).decode().replace('\n', '')

    headers = {
        'authorization': "Basic %s " % BASE64STRING,
        'content-type': "application/json",
        'accept': "application/json"
    }
    
    c = getClusterInformation(
        cParameters[0],
        cParameters[1],
        fsxPassword
    )

    svm = getSVMFromCluster(c, cParameters[3])[0]

    # Using PATCH
    # SAP recommended tcp_max_transfer_size : 262144

    payload = {
        "transport": {
            "tcp_max_transfer_size": cParameters[4]
        }
    }

    svmMaxTxSize=getSvmMaxTxSize(c, svm['uuid'])
    print(svmMaxTxSize)
    
    res = setSVMsdetails(c, svm['uuid'], payload)

    svmMaxTxSize=getSvmMaxTxSize(c, svm['uuid'])
    print(svmMaxTxSize)
    
    cfnresponse.send(event, context, cfnresponse.SUCCESS, event)
    
    # return svmMaxTxSize
