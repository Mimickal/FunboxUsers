#!/bin/bash
coverage run --branch --source=./ --omit=./test/*.py test/runtest.py $1
coverage report
