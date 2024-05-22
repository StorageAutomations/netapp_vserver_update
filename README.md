# netapp_vserver_update

Amazon FSx for NetApp ONTAP is fully managed storage system certified to be used as a NFS storage for SAP HANA in AWS Cloud. Sample code in this repository demonstrates how to use Lambda Function to update a SVM of an Amazon FSx for NetApp ONTAP filesystem.

NetApp provides a rich set of Ontap REST APIs available to manage their Storage Systems. 

Cloudformation is widely used to manage complex deployments using automation frameworks. CloudFormation can invoke a Lambda Function which could also be used to configure the Amazon FSx NetApp filesystems and SVMs on these filesystems using REST APIs. A lambda function when invoked with CloudFormation needs to send a SUCCESS or FAILED response to the CloudFormation stack to proceed to the next stage using `cfn-response` module. 

## References

- NetApp REST [API documentation](https://library.netapp.com/ecmdocs/ECMLP2856304/html/index.html#/)
- Ontap [Automation documentation](https://docs.netapp.com/us-en/ontap-automation/)
- More examples on [Github](https://github.com/NetApp/ontap-rest-python/tree/master)
- [SAP Note 2039883 - FAQ: SAP HANA database and data snapshots](https://launchpad.support.sap.com/#/notes/2039883)
- [SAP Note 3024346 - Linux Kernel Settings for NetApp NFS](https://launchpad.support.sap.com/#/notes/3024346)
- Read more about [`cfn-response`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-lambda-function-code-cfnresponsemodule.html) module and CloudFormation
