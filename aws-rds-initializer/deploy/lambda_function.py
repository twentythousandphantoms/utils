import json
import boto3
import base64
import logging
import pymysql
import psycopg2
from botocore.exceptions import ClientError

# Setting up Logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """
    Create or update users in database, and their secrets in Secret Manager.

    Prerequisites:
     - Required permissions to Secrets Manager

    :param event: Provided by user. JSON-formatted document that contains data for a Lambda function to process
    :param context: Provided by Lambda at runtime. This object provides methods and properties that provide information
    about the invocation, function, and runtime environment.

    :rtype: dict
    :return: status message
    """

    response = {}
    logging.info("lambda_handler: version - legacy 28-06-2021-2")

    sm_client = create_sm_client(event)
    master_secret = get_master_secret(event, sm_client)
    db_client = create_db_client(event, master_secret)
    manage_db_users(event, context, db_client, sm_client, master_secret)
    return response


def create_sm_client(event):
    """
    Set up a Secrete Manager client.
    :param event:
    :return: Service client instance
    """
    session = boto3.session.Session()
    secrets_manager_client = session.client(
        service_name='secretsmanager',
        region_name=event['region']
    )

    return secrets_manager_client


def new_random_password(sm_client):
    """Returns a Random Passwords

   Args:
        sm_client (client): The secrets manager service client
    """

    logger.info("new_random_password: creating")
    # Get exclude characters from environment variable
    exclude_characters = ':/@"\'\\'
    # Generate a random password
    passwd = sm_client.get_random_password(ExcludeCharacters=exclude_characters)
    return passwd['RandomPassword']


def get_master_secret(event, sm_client):
    """
    Get database master user Secret value

    :param event:
    :param sm_client:

    :rtype: dict
    :return: Master Secret value with its arn included
    """

    secret = UserSecret(event['secret_name'], sm_client)
    try:
        logging.info(f'get_master_secret: start')
        secret_value, secret_arn = secret.get()

        # the master_secret_arn will needed for some further operations
        secret_value['master_secret_arn'] = secret_arn

        # backward compatibility with old version of the secrets secretstring format
        if 'database_name' in secret_value:
            secret_value['dbname'] = secret_value['database_name']

        # add master secret tags to master secret dictionary
        secret_value.update(secret.tags)

        return secret_value
    except Exception as e:
        message = f'get_master_secret: An error occurred while getting the master secret.'
        raise type(e)(str(e) + '\n' + message)


def define_db_engine(event, master_secret):
    """
    The RDS engine can be either provided by the user in еру event data or contained in the master user secret.

    :param event:
    :param master_secret:
    :return:
    """

    if 'engine' in master_secret:
        engine = master_secret['engine']
    elif 'engine' in event:
        engine = event['engine']
    elif 'db_engine' in event:
        engine = event['db_engine']
    else:
        message = 'define_db_engine: db_engine is undefined. Please provide the "db_engine" value into the event input'
        raise ValueError(message)
    return engine


def create_db_client(event, master_secret):
    """

    :param event:
    :param master_secret:
    :return:
    """

    # The RDS host can be either provided by the user in еру event data or contained in the master user secret.
    # If it is in both places let's check if they equal
    # If only in one, then we take this value
    if 'rds_host' in event and 'host' in master_secret:
        if event['rds_host'] != master_secret['host']:
            message = f'create_db_client: given rds_host value does not match host value in master_secret ' \
                      f'({event["secret_name"]})'
            raise ValueError(message)
        rds_host = event['rds_host']
    elif 'rds_host' in event:
        rds_host = event['rds_host']
    elif 'host' in master_secret:
        rds_host = master_secret['host']
        event['rds_host'] = master_secret['host']
    else:
        message = f'create_db_client: rds_host is not provided'
        raise ValueError(message)

    engine = define_db_engine(event, master_secret)

    # Initialize the connection to the database depending on its type
    try:
        if engine == 'mysql':

            conn = pymysql.connect(rds_host,
                                   user=master_secret['username'],
                                   passwd=master_secret['password'],
                                   connect_timeout=100,
                                   autocommit=True)
        elif engine == 'postgres':
            conn_string = "host=%s user=%s password=%s dbname=%s" % \
                          (rds_host,
                           master_secret['username'],
                           master_secret['password'],
                           master_secret['dbname'])
            conn = psycopg2.connect(conn_string)
            conn.autocommit = True
        else:
            message = "create_db_client: Unexpected error: db_engine is not set or invalid. " \
                      "Supported values: 'postgres', 'mysql'"
            raise ValueError(message)
    except RuntimeError as e:
        message = f'lambda_handler: Could not connect to database instance ({rds_host}).'
        raise RuntimeError(message) from e

    return conn


def manage_db_users(event, context, db_client, sm_client, master_secret):
    def manage_secrets():
        secret_name = usr_params['user_secret_name'] if 'user_secret_name' in usr_params else 'dummy'
        user_secret = UserSecret(secret_name, sm_client)
        if 'delete' in usr_params and usr_params['delete'].lower() == 'true':
            if user_secret.exists:
                user_secret.drop(usr_params)
        else:
            if not user_secret.exists:
                user_secret.create(event, usr_params, master_secret)
            else:
                user_secret.cancel_rotate_secret()
                user_secret.update(event, usr_params, master_secret)
            user_secret.set_tags(event, usr_params, master_secret, context)

    def init_user(params):
        params['new_passwd'] = new_random_password(sm_client)

        engine = define_db_engine(event, master_secret)

        if engine == 'postgres':
            usr = PostgresUser(db_client, master_secret['dbname'], params)
        elif engine == 'mysql':
            usr = MysqlUser(db_client, master_secret['dbname'], params)
        else:
            message = f"init_user: {engine} user creation is not supported yet"
            raise RuntimeError(message)
        return usr

    # fixing "_clone" rotation function issue
    # master user to assume all ddl roles in postgres. required to make it possible to delete all "_clone" users
    engine = define_db_engine(event, master_secret)

    for usr_params in event['users']:
        if engine == 'postgres' and 'delete' in usr_params and usr_params['delete'].lower() == 'true':
            for u_params in event['users']:
                if 'grant_ddl' in u_params and u_params['grant_ddl'].lower() == 'true':
                    try:
                        user = init_user(u_params)
                        user.grant_role_to_current_user()
                    except Exception as e:
                        logging.info(
                            f"manage_db_users: cannot grant_role_to_current_user: {u_params['db_user']}" + str(e))
            break

    # core logic
    for usr_params in event['users']:
        logging.info(
            f"manage_db_users: Start of processing for user {usr_params['db_user']}")

        user = init_user(usr_params)

        if 'delete' in usr_params and usr_params['delete'].lower() == 'true':
            if user.exists:
                user.drop()
        else:
            if not user.exists:
                user.create()
                user.set_password()

            user.update_privileges()
            if 'update_password' in usr_params and usr_params['update_password'].lower() == 'true':
                user.set_password()

        manage_secrets()
        logging.info(
            f"manage_db_users: End of processing for user {usr_params['db_user']}")


class PostgresUser:

    def __init__(self, db_client, dbname, data):

        self.dbname = dbname
        self.name = data['db_user']
        self.password = data['new_passwd']
        self.secret_name = data['user_secret_name']
        self.grant_ddl = str(data['grant_ddl'])
        self.grant_privileges = data['grant_privileges']
        self.grantor = data['grantor']
        self.db_client = db_client
        self.db_cursor = self.db_client.cursor()

    @property
    def exists(self):
        """
        Check if the given user already exists.

        :rtype: bool
        :return: Either the user exists or not
        """
        query = f"SELECT 1 FROM pg_roles WHERE rolname='{self.name}';"
        self.db_cursor.execute(query)
        if self.db_cursor.rowcount > 0:
            logger.info(f'PostgresUser.exists: the user {self.name} already exists.')
            return True
        else:
            logger.info(f'PostgresUser.exists: the user {self.name} does not exists yet.')
            return False

    def create(self):
        try:
            query = f"CREATE ROLE \"{self.name}\" WITH LOGIN PASSWORD '{self.password}';"
            logger.info(f'PostgresUser.create: Creating the user (ROLE) {self.name}... ')
            self.db_cursor.execute(query)
            logger.info('PostgresUser.create: Done.')
        except Exception as e:
            message = f'PostgresUser.create: An error occurred while creating the user. Query: {query}'
            raise type(e)(str(e) + '\n' + message)

    def drop(self):
        try:
            logger.info(
                f'PostgresUser.drop: Revoke the privileges from the {self.name}... ')
            query = f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{self.name}\";"
            self.db_cursor.execute(query)
            query = f"REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM \"{self.name}\";"
            self.db_cursor.execute(query)
            query = f"REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM \"{self.name}\";"
            self.db_cursor.execute(query)
            query = f"REVOKE ALL PRIVILEGES ON SCHEMA public  FROM \"{self.name}\";"
            self.db_cursor.execute(query)
            if self.has_grantor:
                try:
                    query = f"ALTER DEFAULT PRIVILEGES FOR ROLE \"{self.grantor}\" IN SCHEMA public " \
                            f"REVOKE ALL ON TABLES FROM \"{self.name}\""
                    self.db_cursor.execute(query)
                    query = f"ALTER DEFAULT PRIVILEGES FOR ROLE \"{self.grantor}\" IN SCHEMA public " \
                            f"REVOKE ALL ON SEQUENCES FROM \"{self.name}\""
                    self.db_cursor.execute(query)
                    query = f"ALTER DEFAULT PRIVILEGES FOR ROLE \"{self.grantor}\" IN SCHEMA public " \
                            f"REVOKE ALL ON FUNCTIONS FROM \"{self.name}\" "
                    self.db_cursor.execute(query)
                except Exception as e:
                    message = f'PostgresUser.drop: ' \
                              f'An error occurred while revoking default privileges. Query: {query}'
                    raise type(e)(str(e) + '\n' + message)

            query = f"REVOKE USAGE ON SCHEMA public FROM \"{self.name}\";"
            self.db_cursor.execute(query)
            query = f"REVOKE ALL ON DATABASE \"{self.dbname}\" FROM \"{self.name}\";"
            self.db_cursor.execute(query)

            logger.info('PostgresUser.drop: Done.')
            logger.info(
                f'PostgresUser.drop: Deleting the user {self.name}... ')
            query = f"DROP USER \"{self.name}\";"
            self.db_cursor.execute(query)
            logger.info('PostgresUser.drop: Done.')
        except Exception as e:
            message = f'PostgresUser.drop: An error occurred while deleting the user. Query: {query}'
            raise type(e)(str(e) + '\n' + message)

    def set_password(self):
        try:
            query = f"ALTER ROLE \"{self.name}\" WITH PASSWORD '{self.password}';"
            logger.info(f'PostgresUser.set_password: Set password for role {self.name}... ')
            self.db_cursor.execute(query)
        except Exception as e:
            message = f'PostgresUser.set_password: An error occurred while setting the password. Query: {query}'
            raise type(e)(str(e) + '\n' + message)

    def grant_role_to_current_user(self):
        query = f"GRANT \"{self.name}\" TO CURRENT_USER;"
        logger.info(f'PostgresUser.grant_role_to_current_user: Granting {self.name} to current user... ')
        self.db_cursor.execute(query)

    def update_privileges(self):
        logger.info(f'PostgresUser.update_privileges: Updating for {self.name}.')
        if self.grant_ddl.lower() == 'true':
            self.grant_ddl_operations()
            self.grant_role_to_current_user()
        else:
            self.grant_connect_and_usage()
            self.grant_privileges_on_existing_db_objects()
            self.alter_default_privileges()
        logger.info(f'PostgresUser.update_privileges: Done.')

    def grant_connect_and_usage(self):
        try:
            query = f"GRANT CONNECT ON DATABASE \"{self.dbname}\" TO \"{self.name}\""
            self.db_cursor.execute(query)
            query = f"GRANT USAGE ON SCHEMA public TO \"{self.name}\""
            self.db_cursor.execute(query)
        except Exception as e:
            message = f'PostgresUser.grant_connect_and_usage: ' \
                      f'An error occurred while granting privileges. Query: {query}'
            raise type(e)(str(e) + '\n' + message)

    def grant_privileges_on_existing_db_objects(self):
        """
        define access privileges on already existing objects

        :return:
        """
        try:
            query = f"GRANT {self.grant_privileges} ON ALL TABLES IN SCHEMA public TO \"{self.name}\""
            self.db_cursor.execute(query)
            query = f"GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO \"{self.name}\""
            self.db_cursor.execute(query)
            query = f"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO \"{self.name}\" "
            self.db_cursor.execute(query)
        except Exception as e:
            message = f'PostgresUser.grant_privileges_on_existing_db_objects: ' \
                      f'An error occurred while granting privileges. Query: {query}'
            raise type(e)(str(e) + '\n' + message)

    @property
    def has_grantor(self):
        return self.grantor != 'None'

    def alter_default_privileges(self):
        """
        define default access privileges
        The following scenario covers the most common database use case.
        For finer tuning, require dba intervention for your specific database.

        Docs: https://www.postgresql.org/docs/current/sql-alterdefaultprivileges.html

        :return:
        """
        #  https://dba.stackexchange.com/questions/53914/permission-denied-for-relation-table/53936#53936
        if self.has_grantor:
            try:
                query = f"ALTER DEFAULT PRIVILEGES FOR ROLE \"{self.grantor}\" IN SCHEMA public " \
                        f"GRANT {self.grant_privileges} ON TABLES TO \"{self.name}\""
                self.db_cursor.execute(query)
                query = f"ALTER DEFAULT PRIVILEGES FOR ROLE \"{self.grantor}\" IN SCHEMA public " \
                        f"GRANT USAGE ON SEQUENCES TO \"{self.name}\""
                self.db_cursor.execute(query)
                query = f"ALTER DEFAULT PRIVILEGES FOR ROLE \"{self.grantor}\" IN SCHEMA public " \
                        f"GRANT EXECUTE ON FUNCTIONS TO \"{self.name}\" "
                self.db_cursor.execute(query)
            except Exception as e:
                message = f'PostgresUser.alter_default_privileges: ' \
                          f'An error occurred while granting privileges. Query: {query}'
                raise type(e)(str(e) + '\n' + message)

    def grant_ddl_operations(self):
        try:
            query = f"GRANT ALL ON DATABASE {self.dbname} TO \"{self.name}\""
            self.db_cursor.execute(query)
        except Exception as e:
            message = f'PostgresUser.grant_ddl_operations: ' \
                      f'An error occurred while granting privileges. Query: {query}'
            raise type(e)(str(e) + '\n' + message)


class MysqlUser:

    def __init__(self, db_client, dbname, data):

        self.dbname = dbname
        self.name = data['db_user']
        self.password = data['new_passwd']
        self.grant_privileges = data['grant_privileges']
        self.db_client = db_client
        self.db_cursor = self.db_client.cursor()

        if 'expire_password_after_creation' in data \
                and data['expire_password_after_creation'].lower() == 'true':
            self.expire_password = True
        else:
            self.expire_password = False

    @property
    def exists(self):
        """
        Check if the given user already exists.

        :rtype: bool
        :return: Either the user exists or not
        """
        query = f"SELECT 1 FROM mysql.user WHERE user ='{self.name}';"
        self.db_cursor.execute(query)
        if self.db_cursor.rowcount > 0:
            logger.info(f'MysqlUser.exists: the user {self.name} already exists.')
            return True
        else:
            logger.info(f'MysqlUser.exists: the user {self.name} does not exists.')
            return False

    def create(self):
        try:
            query = f"CREATE USER IF NOT EXISTS '{self.name}'@'%' IDENTIFIED BY '{self.password}';"
            logger.info(f'MysqlUser.create: Creating the user {self.name}... ')
            self.db_cursor.execute(query)
            logger.info('MysqlUser.create: Done.')
        except Exception as e:
            message = f'MysqlUser.create: An error occurred while creating the user. Query: {query}'
            raise type(e)(str(e) + '\n' + message)

    def drop(self):
        try:
            query = f"DROP USER '{self.name}'@'%';"
            logger.info(f'MysqlUser.drop: Deleting the user {self.name}... ')
            self.db_cursor.execute(query)
            logger.info('MysqlUser.drop: Done.')
        except Exception as e:
            message = f'MysqlUser.drop: An error occurred while deleting the user. Query: {query}'
            raise type(e)(str(e) + '\n' + message)

    def expire(self):
        """
        Password-expiration capability, which enables database administrators
        to require that users reset their password.
        https://dev.mysql.com/doc/refman/5.6/en/expired-password-handling.html
        :return:
        """
        try:
            query = f"ALTER USER '{self.name}'@'%' PASSWORD EXPIRE;"
            logger.info(f'MysqlUser.expire: Force the user {self.name} to change his password after first login... ')
            self.db_cursor.execute(query)
            logger.info('MysqlUser.expire: Done.')
        except Exception as e:
            message = f'MysqlUser.expire: An error occurred while password expiration for the user. Query: {query}'
            raise type(e)(str(e) + '\n' + message)

    def set_password(self):
        try:
            query = f"ALTER USER '{self.name}'@'%' IDENTIFIED BY '{self.password}';"
            logger.info(f'MysqlUser.set_password: Setting password for user {self.name}... ')
            self.db_cursor.execute(query)
            logger.info('MysqlUser.set_password: Done.')
            if self.expire_password:
                self.expire()

        except Exception as e:
            message = f'MysqlUser.set_password: An error occurred while setting the password. Query: {query}'
            raise type(e)(str(e) + '\n' + message)

    def update_privileges(self):
        try:
            query = f"GRANT {self.grant_privileges} ON {self.dbname}.* TO {self.name}@'%';"
            logger.info(f'MysqlUser.update_privileges: Granting {self.grant_privileges} for user {self.name}... ')
            self.db_cursor.execute(query)
            logger.info('MysqlUser.update_privileges: Done.')
        except Exception as e:
            message = f'MysqlUser.update_privileges: An error occurred while granting the privileges. Query: {query}'
            raise type(e)(str(e) + '\n' + message)


class UserSecret:

    def __init__(self, name, sm_client):
        """
        Init the secret object

        :param name: The secret name
        :param sm_client: The secrets manager service client
        """

        self.name = name
        self.sm_client = sm_client

    def get(self):
        """
        Get secret from secrets manager

        :rtype secret_value: dict
        :return secret_value: JSON secret value

        :rtype secret_arn: str
        :return secret_arn: Secret ARN string
        """

        try:
            secret_response = self.sm_client.get_secret_value(
                SecretId=self.name)
        except ClientError as e:
            raise e
        else:
            # Decrypts secret using the associated KMS CMK.
            # Depending on whether the secret is a string or binary, one of these fields will be populated.
            if 'SecretString' in secret_response:
                secret_value = secret_response['SecretString']
            else:
                secret_value = base64.b64decode(
                    secret_response['SecretBinary'])
            secret_arn = secret_response['ARN']
            logger.info(f'UserSecret.get: retrieved the secret: {secret_arn}')
            return json.loads(secret_value), secret_arn

    @property
    def tags(self):
        """
        Get secret tags
        :rtype tags: dict
        :return tags: dict of secret tags
        """
        try:
            secret_list_response = self.sm_client.list_secrets(
                Filters=[{'Key': 'name', 'Values': [self.name]}])
        except ClientError as e:
            raise e
        else:
            if len(secret_list_response['SecretList']) == 1:
                print(secret_list_response['SecretList'][0])
                tags_list = secret_list_response['SecretList'][0]['Tags']
                tags_dict = {}
                for tag in tags_list:
                    tags_dict[tag['Key']] = tag['Value']
            else:
                logger.info(f'UserSecret.get_tags: got less or more than 1 secret. ')
                raise
            return tags_dict

    @property
    def exists(self):
        try:
            logging.info(f"UserSecret.exists: checking")
            self.get()
            logger.info(f'UserSecret.exists: the secret {self.name} exists.')
            return True
        except self.sm_client.exceptions.ResourceNotFoundException:
            logger.info(
                f'UserSecret.exists: the secret {self.name} does not exist.')
            return False

    def user_secretstring(self, event_data, usr_data, master_secret) -> str:
        """
        Generate a secretstring

        The Secret SecretString is expected to be a JSON string with the following format:
            {
                'engine': <required: must be set to 'postgres' or 'mysql'>,
                'host': <required: instance host name>,
                'username': <required: username>,
                'password': <required: password>,
                'dbname': <optional: database name, default to 'postgres'>,
                'port': <optional: if not specified, default port 5432 (or 3306) will be used>,
                'masterarn': <required: the arn of the master secret which will be used to create users/change passwords>
            }

        :type event_data: dict
        :param event_data: The Lambda Event data containing some database details to be transferred to secret created

        :type usr_data: dict
        :param usr_data: The database user data containing some user details to be transferred to secret created

        :type master_secret: dict
        :param master_secret: The master secret data containing some details to be transferred to secret created

        :return:
        """

        if ('update_password' in usr_data and usr_data['update_password'] == 'true') or not self.exists:
            passwd = usr_data['new_passwd']
            logger.info(f'UserSecret.user_secretstring: generated with new password')
        else:
            cur_secret_value, _ = self.get()
            passwd = cur_secret_value['password']
            logger.info(f'UserSecret.user_secretstring: generated with old password (wont be updated)')

        user_secret_dict = {
            "engine": define_db_engine(event_data, master_secret),
            "host": event_data['rds_host'],
            "username": usr_data['db_user'],
            "password": passwd,
            "dbname": master_secret['dbname'],
            "port": master_secret['port'],
            "masterarn": master_secret['master_secret_arn'],
            "clusterIdentifier": master_secret['clusterIdentifier'],
            "dbInstanceIdentifier": master_secret['dbInstanceIdentifier']
        }

        # Make the secret JSON string
        user_secret_str = json.dumps(user_secret_dict)

        if "log_secretstring" in usr_data and usr_data["log_secretstring"] == "true":
            logger.info(f"UserSecret.user_secretstring: {user_secret_dict}")

        return user_secret_str

    def create(self, event_data, usr_data, master_secret) -> None:
        """
        Generate a new secret

        Docs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/secretsmanager.html
        #SecretsManager.Client.create_secret


        :type event_data: dict
        :param event_data: The Lambda Event data containing some database details to be transferred to secret created

        :type usr_data: dict
        :param usr_data: The database user data containing some user details to be transferred to secret created

        :type master_secret: dict
        :param master_secret: The master secret data containing some details to be transferred to secret created

        :returns None
        """
        if not 'create_secret' in usr_data or not usr_data['create_secret'].lower() == 'false':
            try:

                response_dict = self.sm_client.create_secret(
                    Name=self.name,
                    Description=f'Secret for \
                    RDS {master_secret["clusterIdentifier"]} \
                    db {master_secret["dbname"]} \
                    user {usr_data["db_user"]}',
                    KmsKeyId=event_data['kms_key_id'],
                    # event_data['kms_key_id'],
                    SecretString=self.user_secretstring(
                        event_data, usr_data, master_secret)
                )
                secrets_creation_message = f"New secret for {usr_data['db_user']} " \
                                           f"successfully created: {response_dict['ARN']} "
                logger.info("UserSecret.create: " + secrets_creation_message)
            except Exception as e:
                message = f'UserSecret.create: An error occurred while creating the secret.'
                raise type(e)(str(e) + '\n' + message)
        else:
            self.user_secretstring(event_data, usr_data, master_secret)

    def update(self, event_data, usr_data, master_secret) -> None:
        try:
            response_dict = self.sm_client.update_secret(
                SecretId=self.name,
                Description=f'Secret for \
                RDS {master_secret["clusterIdentifier"]} \
                db {master_secret["dbname"]} \
                user {usr_data["db_user"]}',
                KmsKeyId=event_data['kms_key_id'],
                SecretString=self.user_secretstring(
                    event_data, usr_data, master_secret)
            )
            secrets_creation_message = f"The secret for {usr_data['db_user']} " \
                                       f"successfully updated: {response_dict['ARN']} "
            logger.info("UserSecret.update: " + secrets_creation_message)
        except Exception as e:
            message = f'UserSecret.update: An error occurred while updating the secret.'
            logger.info(message)
            raise e

    def set_tags(self, event_data, usr_data, master_secret, context=None) -> None:
        try:
            if 'rotate' not in usr_data or usr_data['rotate'].lower() not in ['false', 'N', False]:
                rotate_flag = 'Y'
            else:
                rotate_flag = 'N'

            tags = [
                    {
                        'Key': 'Name',
                        'Value': self.name
                    },
                    {
                        'Key': 'emailId',
                        'Value': master_secret["resource-owner"]
                    },
                    {
                        'Key': 'type',
                        'Value': 'RDS'
                    },
                    {
                        'Key': 'rotate',
                        'Value': rotate_flag
                    },
                    {
                        'Key': 'rotationInterval',
                        'Value': '60'
                    },
                    {
                        'Key': 'rotationLambdaFunction',
                        'Value': self.rotation_function_arn(event_data, context)
                    }
                ]

            self.sm_client.tag_resource(
                SecretId=self.name,
                Tags=tags
            )

            secrets_creation_message = f"The secret for {usr_data['db_user']} " \
                                       f"successfully tagged: {tags} "
            logger.info("UserSecret.set_tags: " + secrets_creation_message)
        except Exception as e:
            message = f'UserSecret.set_tags: An error occurred while updating the secret.'
            logger.info(message)
            raise e

    def cancel_rotate_secret(self):
        try:
            logger.info("UserSecret.cancel_rotate_secret: Attempting to disable the automatic scheduled rotation "
                        "configured earlier as Maestro will now do so")
            response_dict = self.sm_client.cancel_rotate_secret(
                SecretId=self.name,
            )
            secrets_rotation_message = f"Successfully cancelled the rotation for secret {self.name}. "
            logger.info("UserSecret.cancel_rotate_secret: " + secrets_rotation_message)
        except Exception as e:
            message = f'UserSecret.cancel_rotate_secret: ERROR occurred while canceling the rotation for the ' \
                      f'secret {self.name}. '
            logging.info(message)
            raise e

    def drop(self, usr_data) -> None:
        try:
            response_dict = self.sm_client.delete_secret(
                SecretId=self.name,
                ForceDeleteWithoutRecovery=True
            )

            secrets_creation_message = f"The secret for {usr_data['db_user']} " \
                                       f"successfully deleted: {response_dict} "
            logger.info("UserSecret.drop: " + secrets_creation_message)
        except Exception as e:
            message = f'UserSecret.drop: An error occurred while deleting the secret {self.name}.'
            raise type(e)(str(e) + '\n' + message)

    @staticmethod
    def rotation_function_arn(event_data, context):
        if 'rotation_function_arn' not in event_data:
            logger.info(
                f"UserSecret.set_rotation: No rotation_function_arn was given")
            rds_host_name = "-".join(
                event_data['rds_host'].split(".")[0].split("-")[:-1])

            logger.debug(f"rds_host_name: {rds_host_name}")

            rds_host_env = event_data['rds_host'].split(".")[0].split("-")[-1]

            if 'rotation_function_scheme' not in event_data:
                rotation_function_scheme = 'single-user-rotation'
            else:
                rotation_function_scheme = event_data['rotation_function_scheme']

            rotation_function_name = rds_host_name.replace("db", "lmd") + \
                                     '-' + rotation_function_scheme + '-' + rds_host_env

            logger.debug(f"rotation_function_name: {rotation_function_name}")

            logger.debug(
                f"UserSecret.set_rotation: rotation_function_name = {rotation_function_name}")
            separator = ":"
            logger.debug(f"UserSecret.set_rotation: separator = {separator}")
            logger.debug(
                f"UserSecret.set_rotation: context.invoked_function_arn = {context.invoked_function_arn}")
            blank_arn = context.invoked_function_arn.split(separator)[:6]
            logger.debug(f"UserSecret.set_rotation: blank_arn = {blank_arn}")
            logger.debug(
                f"UserSecret.set_rotation: separator.join(blank_arn) = {separator.join(blank_arn)}")
            rotation_function_arn = separator.join(
                blank_arn) + separator + rotation_function_name
            logger.info(
                f"UserSecret.set_rotation: rotation_function_arn generated: " + rotation_function_arn)
        else:
            rotation_function_arn = event_data['rotation_function_arn']

        return rotation_function_arn