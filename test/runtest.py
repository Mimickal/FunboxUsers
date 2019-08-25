'''This script allows us to run Pocha with test coverage.
It's a wee bit hacky, since it hooks into Pocha's internal implementation,
but it works!
'''
from os import environ

from pocha import cli

environ['FB_USERS_DB'] = ':memory:'

cli.cli()
