#!/bin/bash
echo "q" > sudo ./mysql_start.sh
sudo mysql -u root -e "CREATE USER 'SSCServer'@'localhost' IDENTIFIED BY 'passphrase'"
sudo mysql -u root -e "GRANT ALL PRIVILEGES ON *.* to 'SSCServer'@'localhost' IDENTIFIED BY 'passphrase'"

