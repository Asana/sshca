#!/usr/bin/python

# Generates a keypair, generates a CSR, and sends it to server for signing

# TODO: clean code (I would never declare the code is clean so this is forever)
# TODO: Encrypt the private key on disk and use an askpass hack to feed it to
#       ssh-agent. Could pass the encryption key through environment, but ooky

import ConfigParser
import getpass
import json
import os
import pwd
import shutil
import sys
import subprocess
import tempfile

CONFIG_FILE_NAME = "/Users/manoj/ssh/getcert.cfg"

def load_config(config_file_name, default_principal):
  pw = pwd.getpwuid(os.getuid())
  whoami = pw[0]
  defaults = {'principal': default_principal};
  config = ConfigParser.SafeConfigParser(defaults = defaults)
  config.read(config_file_name)
  return config

def generate_keypair(keypair_file_name):
  with open("/dev/null") as devnull:
    subprocess.check_call(("ssh-keygen", "-f", keypair_file_name, "-P", ""),
                          stdin=devnull, stdout=devnull)

def read_public_key(keypair_file_name):
  with open(keypair_file_name) as key:
    return key.read()

def unregister_old_key(keypair_file_name):
  # If this doesn't work, it might just not be present. Ignore the exit code
  with open("/dev/null") as devnull:
    subprocess.call(("ssh-add", "-d", keypair_file_name),
                    stdin=devnull, stdout=devnull, stderr=devnull)

def register_new_key(keypair_file_name):
  with open("/dev/null") as devnull:
    subprocess.check_call(("ssh-add", keypair_file_name),
                          stdin=devnull, stdout=devnull)

def main():
  pw = pwd.getpwuid(os.getuid())
  whoami = pw[0]
  home_dir = pw[5]
  config = load_config(CONFIG_FILE_NAME, default_principal=whoami)
  keypair_file_name = os.path.join(home_dir, ".ssh", "spoon")
  unregister_old_key(keypair_file_name)
  try:
    os.remove(keypair_file_name)
  except OSError as e:
    if e.errno == os.errno.ENOENT:
      pass
  generate_keypair(keypair_file_name)

  subprocess.check_call((os.path.join(os.path.dirname(sys.argv[0]), "getsig.py"),
                        "user", config.get("user", "principal"),
			keypair_file_name,))

  register_new_key(keypair_file_name)

if __name__ == "__main__":
  main()
