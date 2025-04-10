#!/bin/bash

mkdir -p ~/Wazuh
cd ~/Wazuh

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

sudo apt update && sudo apt upgrade && sudo apt-get install debconf adduser procps curl gnupg apt-transport-https filebeat debhelper libcap2-bin

curl -sO https://packages.wazuh.com/4.11/wazuh-certs-tool.sh
curl -sO https://packages.wazuh.com/4.11/config.yml

##Modification du fichier config.yml

bash ./wazuh-certs-tool.sh -A
tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .
rm -rf ./wazuh-certificates

sudo apt install wazuh-indexer wazuh-manager wazuh-dashboard -y

##Modification du fichier /etc/wazuh-indexer/opensearch.yml

./deploy-cert-indexer.sh

systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl start wazuh-indexer

/usr/share/wazuh-indexer/bin/indexer-security-init.sh

systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager
systemctl status wazuh-manager

apt install filebeat #Installation du paquet filebeat
curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.7/tpl/wazuh/filebeat/filebeat.yml #Téléchargement du fichier de confuguration filebeat

##Midification du fichier /etc/filebeat/filebeat.yml

filebeat keystore create #Création du fichier Keystore

echo admin | filebeat keystore add username --stdin --force
echo admin | filebeat keystore add password --stdin --force

curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v4.7.2/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json

curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.3.tar.gz | tar -xvz -C /usr/share/filebeat/module

./deploy-cert-filebeat.sh

systemctl daemon-reload
systemctl enable filebeat
systemctl start filebeat

##Modification du fichier /etc/wazuh-dashboard/opensearch_dashboards.yml

./deploy-cert-dashboard.sh

systemctl daemon-reload
systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard
