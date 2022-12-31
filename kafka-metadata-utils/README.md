# kafka-metadata-utils

The scripts are supposed to use in order to complete the step "Export cluster-A topics specific configuration, import into cluster-B; (Kafka cli for the cluster with lots of topics, use BBG for the cluster with just a few topics)" from the runbook: [Jarvis Platform 2.0 upgrade via migration](https://www.linkedin.com/in/abr/) 

topics_metadata_export.sh
------

The script exports kafka topics list and their configs and prepares a CSV file __topics.csv__.  

**Usage:**  

```commandline
# Copy the script into a broker container (Source Cluster)
ab@ANDREIs-MacBook-Pro scripts % kubectl cp topics_metadata_export.sh kafka-0:/home/kafka -n main -c broker

# Log in to the broker and run the scrpit
ab@ANDREIs-MacBook-Pro scripts % k exec -n main kafka-0 -c broker -it -- bash
kafka@kafka-0:/$ cd
kafka@kafka-0:~$ bash topics_metadata_export.sh

# After complete, you'll fine the artifact at the same directory
kafka@kafka-0:~$ ls
topics.csv  topics_metadata_export.sh

# Exit from the broker and copy the topics.csv to your local computer
kafka@kafka-0:~$ exit
exit
ab@ANDREIs-MacBook-Pro scripts % kubectl cp kafka-0:/home/kafka/topics.csv topics.csv  -n main -c broker 
```


topics_metadata_import.sh
------

The script creates kafka topics from a provided csv config file __topics.csv__.  

**Usage:**  

```commandline
# Copy the script and the config file into a broker container (Target Cluster)
ab@ANDREIs-MacBook-Pro scripts % kubectl cp topics_metadata_export.sh kafka-0:/home/kafka -n main -c broker
ab@ANDREIs-MacBook-Pro scripts % kubectl cp topics.csv kafka-0:/home/kafka -n main -c broker

# Log in to the broker and run the scrpit
ab@ANDREIs-MacBook-Pro scripts % k exec -n main kafka-0 -c broker -it -- bash
kafka@kafka-0:/$ cd
kafka@kafka-0:~$ bash topics_metadata_import.sh
```

Example Output:
```commandline
...
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9000 --create --topic ads_rtcrd__pkg_prd_vrsn --partitions 1 --replication-factor 3 --config compression.type=lz4 --config min.insync.replicas=2 --config segment.bytes=1073741824 --config message.format.version=2.7-IV2 --config max.message.bytes=2000000
WARNING: The configuration message.format.version=2.7-IV2 is specified. This configuration will be ignored if the version is newer than the inter.broker.protocol.version specified in the broker.
WARNING: Due to limitations in metric names, topics with a period ('.') or underscore ('_') could collide. To avoid issues it is best to use either, but not both.
Created topic ads_rtcrd__pkg_prd_vrsn.
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9000 --create --topic conformance_target_conprpsl__prpsl_extrnl_xmap --partitions 1 --replication-factor 3 --config compression.type=lz4 --config min.insync.replicas=2 --config segment.bytes=1073741824 --config message.format.version=2.7-IV2 --config max.message.bytes=2000000
WARNING: The configuration message.format.version=2.7-IV2 is specified. This configuration will be ignored if the version is newer than the inter.broker.protocol.version specified in the broker.
WARNING: Due to limitations in metric names, topics with a period ('.') or underscore ('_') could collide. To avoid issues it is best to use either, but not both.
Created topic conformance_target_conprpsl__prpsl_extrnl_xmap.
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9000 --create --topic ads_rtcrd__rate_card --partitions 1 --replication-factor 3 --config compression.type=lz4 --config min.insync.replicas=2 --config segment.bytes=1073741824 --config message.format.version=2.7-IV2 --config max.message.bytes=2000000
WARNING: The configuration message.format.version=2.7-IV2 is specified. This configuration will be ignored if the version is newer than the inter.broker.protocol.version specified in the broker.
WARNING: Due to limitations in metric names, topics with a period ('.') or underscore ('_') could collide. To avoid issues it is best to use either, but not both.
Created topic ads_rtcrd__rate_card.
...
```