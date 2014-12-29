#!/usr/bin/python

# CA signer, suitable for running as an sshd subsystem

# TODO: make clear that ForceCommand should be banned as any user that runs this

# TODO: clean code (I would never declare the code is clean so this is forever)
# TODO: logging sure would be nice
# TODO: Letting users specify more restrictive validity intervals
# TODO: DoS protection, e.g. maximum CSR size to prevent DoS
# TODO: Key IDs are not unique (ms make it tough but not impossible to dup)
# TODO: Custom JSON loader so we can verify syntax and have a nicer object
# TODO: subprocess return code negative means signal. Should deal with that?
# TODO: ssh subsystems don't seem to do anything with stderr; we should get it

import ConfigParser
import datetime
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile

CONFIG_FILE_NAME = "/home/ubuntu/ssh/signer.cfg"
DATE_FORMAT = "{:%Y%m%d%H%M%S%f}"
PUBLIC_KEY_FILE_NAME = "gir.pub"
CERTIFICATE_FILE_NAME = "gir-cert.pub"

CERTIFICATE_FLAGS = \
  ( 'X11-forwarding', 'agent-forwarding', 'port-forwarding', 'pty', 'user-rc')

class Error(Exception):
  def __init__(self, value):
    self.value = value
  def __str__(self):
    return repr(self.value)

class CSRPrincipalError(Error):
  pass

class CSRFormatError(Error):
  pass

class PermissionDeniedError(Error):
  pass

def validate_user_csr(config, csr, whoami):
  if csr['principal'] != whoami:
    print >>sys.stderr, "{} may not mint certs for {}".format(
        whoami, csr['principal'])
    sys.exit(1)

# TODO: Perhaps shut this mechanism off, and use ForceCommand for it too
# That would mean needing a separate user for people signing host keys, since
# there's no way to specify a different set of users in sshd_config without
# a different command line, meaning a different ForceCommand
def validate_host_csr(config, csr, whoami):
  if whoami not in config.get('host', 'allowed_requestors', "").split():
    print >>sys.stderr, whoami + " can't have host key signatures."
    sys.exit(1)

def validate_csr(config, csr):
  type = csr['type']
  # ssh uses getpw* for user details instead of envars. So we do the same.
  whoami = pwd.getpwuid(os.getuid())[0]
  if type == "user":
    validate_user_csr(config, csr, whoami)
  elif type == "host":
    validate_host_csr(config, csr, whoami)
  else:
    print >>sys.stderr, 'Certificate type of "%s" unsupported'
    sys.exit(1)

def load_config(config_file):
  defaults = dict()
  for flag in CERTIFICATE_FLAGS:
    defaults["permit-" + flag] = "true"
  config = ConfigParser.SafeConfigParser(defaults = defaults)
  config.readfp(config_file)
  return config

def construct_cert_option_flags(config, csr):
  cert_type = csr['type']
  # Host certs have no options so far
  if cert_type != "user":
    return []
  keygen_cert_option_flags = ["-O", "clear"]
  for flag in CERTIFICATE_FLAGS:
    if config.getboolean(cert_type, "permit-" + flag) and \
       csr.get("permit-" + flag, True):
      keygen_cert_option_flags.extend(("-O", "permit-" + flag))
    else:
      keygen_cert_option_flags.extend(("-O", "no-" + flag))

  for option in ("force-command", "source-address"):
    if config.has_option(cert_type, option):
      keygen_cert_option_flags.extend(("-O", option + "=" +
                                 config.get(cert_type, option)))
    elif option in csr:
      keygen_cert_option_flags.extend(("-O", option + "=" + csr[option]))

  return keygen_cert_option_flags

def construct_cert_type_flags(config, csr):
  if csr['type'] == "host":
    return ["-h"]
  else:
    return []

def main():
  with open(CONFIG_FILE_NAME) as config_file:
    config = load_config(config_file)
  csr = json.load(sys.stdin)

  validate_csr(config, csr)
  cert_type = csr.get('type', None)
    
  # TODO: Refactor this block into a function once I figure out the right API
  try:
    temp_dir_name = tempfile.mkdtemp()
    with open(os.path.join(temp_dir_name, PUBLIC_KEY_FILE_NAME), "w") as pubkey:
      pubkey.write(csr['public_key'])
    cert_identity = csr['principal'] + "/" + \
                    DATE_FORMAT.format(datetime.datetime.now())
    with open("/dev/null") as devnull:
      error = subprocess.check_call(["ssh-keygen",
                                     "-s", config.get(cert_type, 'ca_file'),
                                     "-I", cert_identity,
                                     "-n", csr['principal'],
                                     "-V", config.get(cert_type, 'validity')] +
                                    construct_cert_option_flags(config, csr) +
                                    construct_cert_type_flags(config, csr) +
                                    [pubkey.name],
                                    stdin=devnull, stdout=devnull,
 #                                   stderr=sys.stdout,
                                    close_fds=True)

    with open(os.path.join(temp_dir_name, CERTIFICATE_FILE_NAME)) as cert:
      sys.stdout.write(cert.read())
     
  finally:
    shutil.rmtree(temp_dir_name)
  
if __name__ == "__main__":
  main()
