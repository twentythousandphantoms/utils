AWS RDS Initializer
=

Here is an example of my work. It combines knowledge of Python, databases (postgresql, mysql), AWS Lambda, AWS RDS (Relational Database Service), Hashicorp Terraform and other AWS services.

Overview
-
This is an Amazon RDS Initializer, which used to create a number of database (postgresql and mysql) users in a automated pipeline.  

### AWS Lambda Function 

The core file is an AWS Lambda function (deploy/lambda_function.py). The abilities of this program includes: 

1. Connect to AWS Services (Secrets, RDS)
2. Retrieve, create, update and delete database users secrets in AWS Secrets service
3. Configure secrets rotation
4. Connect to RDS databases and create database users with a specified privileges 
   1. It supports both PostgreSQL and MySQL
      1. ***PostgreSQL***. Given the complexity of users privileges and relationships in PostgreSQL, it can set and manage privileges and relationships effectively and correctly. 
   2. Is also can update (including passwords and privileges) and delete users taking into accounts their secrets thate are stored in AWS Secrets service.


This Lambda function uses an input event (JSON-formatted document that contains data for a Lambda function to process)  

***Input Example:***
```commandline
{
    "secret_name": "dp-sec-db-ue1-af-activation-master_user-dev",
    "database_name": "airflow",
    "rds_host": "dp-db-ue1-af-activation-dev.cluster-xxxxxxxxxxxx.us-east-1.rds.amazonaws.com",
    "region": "us-east-1",
    "kms_key_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "db_engine":"postgres",
    "users": [
      {
         "db_user":"airflow-rw-ddl",
         "user_secret_name":"dp-sec-db-ue1-af-activation-af_rw_ddl-dev",
         "grant_ddl":"true",
         "grant_privileges":"SELECT,INSERT,UPDATE,DELETE,TRUNCATE",
         "grantor":"None"
      },
      {
         "db_user":"airflow-rw-dml",
         "user_secret_name":"dp-sec-db-ue1-af-activation-af_rw-dev",
         "grant_ddl":"false",
         "grant_privileges":"SELECT,INSERT,UPDATE,DELETE",
         "grantor":"airflow-rw-ddl"
      },
      {
         "db_user":"airflow-ro-dml",
         "user_secret_name":"dp-sec-db-ue1-af-activation-af_ro-dev",
         "grant_ddl":"false",
         "grant_privileges":"SELECT",
         "grantor":"airflow-rw-ddl"
      }
   ]
}
```


Using the example above, the Lambda function creates three postgres database users in the specified RDS, keeping the needed relationships between these users. (One is DDL main user - `airflow-rw-ddl`, who grants access to two another users - `airflow-rw-dml` and `airflow-ro-dml`).  
   
You can find more examples under the `lambda-invocation` directory

### Secrets management and rotation

Since the database users are supposed to use by some tools and programs that are reside in AWS, their credentials should be available through the AWS Secrets service. So that that tools and programs can retrace the credentials and connect to database automatically.
This RDS Initializer takes care about this. It can
- Create, update and delete the credentials/secrets in sync with the actual values in RDS database
- Set and unset a secrets rotation according to official AWS recommended way in case a custom rotation functions is not specified 

Usage
-
This tool is widely used by one my customers to manage hundreds of RDS database users in tens of PostgreSQL/MySQL databases. It dramatically increased the speed of database environments deployment since it is used in the Jenkins pipeline. 
