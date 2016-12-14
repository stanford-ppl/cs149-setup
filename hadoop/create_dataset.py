#!/usr/bin/env python

# Before running this script:
#
# bunzip2 enwiki-latest-pages-articles.xml.bz2
# mkdir all
# cd all
# split -a 3 -b 64m ../enwiki-20130102-pages-articles.xml chunk_
# cd ..
#
# Then:
#
# .../create_dataset.py all 64 8gb 8192
# .../create_dataset.py all 64 4gb 4096
# .../create_dataset.py all 64 2gb 2048
# .../create_dataset.py all 64 1gb 1024

import os, random, shutil, sys

def choose_chunks(all_dir, chunk_size, dest_dir, dest_size):
    all_chunks = os.listdir(all_dir)
    num_chunks = dest_size/chunk_size
    dest_chunks = random.sample(all_chunks, num_chunks)
    os.mkdir(dest_dir)
    for chunk in dest_chunks:
        shutil.copyfile(
            os.path.join(all_dir, chunk),
            os.path.join(dest_dir, chunk))

if __name__ == '__main__':
    assert len(sys.argv) == 5
    choose_chunks(
        sys.argv[1],
        int(sys.argv[2]),
        sys.argv[3],
        int(sys.argv[4]))
