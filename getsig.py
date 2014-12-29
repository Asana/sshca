#!/usr/bin/python

# TODO: use argparse instead of the janky way I'm doing it now

import ConfigParser
import json
import subprocess
import sys

CONFIG_FILE_NAME = "/Users/manoj/ssh/getcert.cfg"

def load_config(config_file_name):
  config = ConfigParser.SafeConfigParser()
  config.read(config_file_name)
  return config

def read_public_key(key_file_name):
  with open(key_file_name) as key:
    return key.read()

def main(argv):
  config = load_config(CONFIG_FILE_NAME)
  cert_type = argv[1]
  principal = argv[2]
  if argv[3].endswith(".pub"):
    key_base_name = argv[3][0:-4]
  else:
    key_base_name = argv[3]

  csr = {
    "type": cert_type,
    "principal": principal,
    "public_key": read_public_key(key_base_name + ".pub")
  }
  cert_file_name = key_base_name + "-cert.pub"
  print >>sys.stderr, "Connecting to CA..."
  with open(cert_file_name, "w") as cert_file:
    signer_subprocess = subprocess.Popen(config.get(cert_type, "ca_command"),
                                      shell=True,
                                      stdin=subprocess.PIPE,
                                      stdout=cert_file)
 
    json.dump(csr, signer_subprocess.stdin)
    signer_subprocess.stdin.close()
    ret = signer_subprocess.wait()
    if ret:
      print >>sys.stderr, "CA signing failed"
      sys.exit(signer_subprocess.returncode)
  
if __name__ == "__main__":
  main(sys.argv)
