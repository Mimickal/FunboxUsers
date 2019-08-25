#!/bin/bash
coverage run --branch --source=./,test/ test/runtest.py $1
coverage report
