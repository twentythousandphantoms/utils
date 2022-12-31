#!/bin/bash
topicConfigsFile="/home/kafka/topics.txt"
topicConfigsCSV="/home/kafka/topics.csv"
true > ${topicConfigsCSV}
printf "Topic:PartitionCount:ReplicationFactor:Configs\n" >> ${topicConfigsCSV}
topicConfigs="/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9000 --topics-with-overrides --describe"
${topicConfigs} > ${topicConfigsFile}
while IFS=: read -r line
do
  Topic=$(echo "${line}"|awk '{print $2}')
  PartitionCount=$(echo "${line}"|awk '{print $4}')
  ReplicationFactor=$(echo "${line}"|awk '{print $6}')
  Configs=$(echo "${line}"|awk '{print $8}')
  if [ "$Topic" != "TOPIC" ] && [ "$Topic" != "" ] && [ "$Topic" != "-" ]
    then
      printf "%s:%s:%s:%s\n" "$Topic" "$PartitionCount" "$ReplicationFactor" "$Configs" >> ${topicConfigsCSV}
    fi
done < "${topicConfigsFile}"
