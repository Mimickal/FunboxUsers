from argparse import ArgumentParser

import util

DEFAULT_CONFIG_PATH = 'config.yaml'

# Load in CLI and YAML config
_parser = ArgumentParser(description='Funbox user account server')
_parser.add_argument(
	'--config-path', type=str, default=DEFAULT_CONFIG_PATH,
	help='Path to the YAML server config file.'
)
_cli_args = _parser.parse_args()
_config = util.loadYaml(_cli_args.config_path)


# Abstract config data structure using poorly named getters
def serviceName():
	return _config['service_name']

def rateLogin():
	return _config['rate_login']

def rateReset():
	return _config['rate_reset']

def rateConfirm():
	return _config['rate_confirm']

def devHTTPSEnabled():
	return _config['https']['enabled']

def devHTTPSCertFile():
	return _config['https']['cert_file']

def devHTTPSKeyFile():
	return _config['https']['key_file']

def host():
	return _config['host']

def port():
	return _config['port']

def debug():
	return _config['default']

