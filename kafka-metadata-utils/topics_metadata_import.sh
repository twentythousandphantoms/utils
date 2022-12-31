#!/bin/bash
topicConfigsCSV="topics.csv"
while IFS=: read -r line
do
  Topic=$(echo "${line}"|awk -F: '{print $1}')
  PartitionCount=$(echo "${line}"|awk -F: '{print $2}')
  ReplicationFactor=$(echo "${line}"|awk -F: '{print $3}')
  Configs=$(echo "${line}"|awk -F: '{print $4}')
  if [ "$Topic" != "Topic" ] && [ "$Topic" != "" ] && [ "$Topic" != "-" ]
    then
      topicConfigArgs=${Configs//,/ --config }
      topicCreate="/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9000 --create --topic ${Topic} --partitions ${PartitionCount} --replication-factor ${ReplicationFactor} --config ${topicConfigArgs}"
      echo "${topicCreate}"
      ${topicCreate}
    fi
done < "${topicConfigsCSV}"

