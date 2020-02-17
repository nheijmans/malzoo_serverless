from hashlib import md5 as md5sum
from hashlib import sha1 as sha1sum

def get_md5(sample):
    """ Generate MD5 of the sample """
    with open(sample, 'rb') as f:
        md5_hash = md5sum(f.read()).hexdigest()

    return md5_hash

def get_sha1(sample):
    """  Generate SHA-1 of the sample """
    with open(sample, 'rb') as f:
        sha1_hash = sha1sum(f.read()).hexdigest()

    return sha1_hash
