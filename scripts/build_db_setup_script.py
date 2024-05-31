#!/usr/bin/python3

import os
import re
import sys

from dotenv import load_dotenv
load_dotenv() 

WORKDIR = os.getenv("DB_MIGRATIONS_PATH") or "./migrations"
TARGET = os.getenv("DB_SETUP_SCRIPT_PATH") or "./migrations/.postgres/setup.sql"
REGEX = os.getenv("DB_FILE_REGEX") or "up.sql"

regex = re.compile(REGEX)

def main() -> int:
    print("Browsing for migration files at ...")
    
    target_dirname = os.path.dirname(TARGET)
    if not os.path.exists(target_dirname):
        os.mkdir(target_dirname)

    scripts = []
    
    for root, _, files in os.walk(WORKDIR):
        files = filter(lambda filename: regex.match(filename), files)
        files = map(lambda filename: os.path.join(root, filename), files)
        scripts += list(files)

    if not scripts:
        print("No migration files where found")
        return 1

    target = open(TARGET, "w")
    for path in sorted(scripts):
        print(f"-\t{path}")

        fo = open(path, "r")
        content = fo.read()
        fo.close()

        target.write(f"{content}\n")

    target.close()
    return 0

if __name__ == '__main__':
    sys.exit(main())