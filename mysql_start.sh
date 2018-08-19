#!/bin/bash
echo "Starting the mysql daemon"
sudo service mysql start || sudo service mysqld start
sudo service mysql status || sudo service mysqld status
