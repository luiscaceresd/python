import argparse, os, magic, hashlib, pefile, yara

def get_files(path):
  if os.path.isdir(path):
    files = []
    for item in os.listdir(path):
      pth = os.path.join(path, item)
      if os.path.isfile(pth):
        files.append(pth)
    return files
  if os.path.isfile(path):
    return [path]
  
def get_file_hashes(path):
  md5 = hashlib.md5()
  sha1 = hashlib.sha1()
  sha256 = hashlib.sha256()
  with open(path, 'rb') as f:
    chunk = f.read(4096)
    while len(chunk) > 0:
      md5.update(chunk)
      sha1.update(chunk)
      sha256.update(chunk)
      chunk = f.read(4096)
  return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}

def get_imphash(path):
  try:
    pe = pefile.PE(path)
    return pe.get_imphash()
  except:
    return "[!] Err: Invalid PE header"
  
def match_yara(file_path, rule_path):
  rule = yara.compile(rule_path)
  matches = rule.match(file_path)
  for m in matches:
    print(" [!] :", m.rule)

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("path", help="The path to the corresponding file or directory")
  parser.add_argument("-s", "--file_summary", help="Get the file type and hashes", action="store_true")
  parser.add_argument("-y", "--yara_scan", help="Scan file or directory with Yara rule", metavar="YARA_RULE_PATH")
  args = parser.parse_args()

  if not os.path.exists(args.path):
    print("[!] Err: Invalid path")
    exit()

  files = get_files(args.path)

  if args.file_summary:
    for file in files:
      print("\n", file)
      fs = "{0:>10} : {1}"
      print(fs.format("type", magic.from_file(file)))
      hashes = get_file_hashes(file)
      print(fs.format("md5", hashes["md5"]))
      print(fs.format("sha1", hashes["sha1"]))
      print(fs.format("sha256", hashes["sha256"]))
      print(fs.format("imphash", get_imphash(file)))
    print()

  if args.yara_scan:
    if os.path.exists(args.yara_scan):
      for file in files:
        print(file)
        match_yara(file, args.yara_scan)
    else:
      print("[!] Err: Invalid Yara rule path")