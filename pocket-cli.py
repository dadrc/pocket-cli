#!/usr/bin/env python3
import sys
import argparse
import configparser
import json
from urllib.parse import urlencode, parse_qsl, parse_qs
from urllib.request import urlopen, Request
from os.path import isfile, expanduser

# TODO change token and code to None for better readability.
# TODO check if config supports that.

# config
api_base = 'https://getpocket.com/v3/'
add_url = api_base + 'add'
request_url = api_base + 'oauth/request'
authorize_url = api_base + 'oauth/authorize'
get_url = api_base + 'get'
modify_url = api_base + 'send'


class AuthHandler:
    key = '11411-11f6716adafdbf8ee3401509'
    rc_file = expanduser('~/.pocketrc')
    config = configparser.ConfigParser(allow_no_value=True)
    token = ""

    def __init__(self, verbose):
        self.verbose = verbose
        # load config, perform oauth if necessary
        if (not isfile(self.rc_file)):
            print("Config file not found, recreating.")
            self.config['OAUTH'] = {
                'code': '',
                'token': ''
            }
            with open(self.rc_file, 'w') as configfile:
                self.config.write(configfile)

        self.config.read(self.rc_file)
        code = self.config['OAUTH']['code']
        self.token = self.config['OAUTH']['token']
        if (self.token == '' and code == ''):
            # no token, no code, start oauth
            code = self.oauth_code(self.key)
            self.config['OAUTH']['code'] = code
            with open(self.rc_file, 'w') as configfile:
                self.config.write(configfile)
            exit()
        elif (self.token == ''):
            # got code, get token
            self.token = self.oauth_token(self.key, code)
            self.config['OAUTH']['token'] = self.token
            with open(self.rc_file, 'w') as configfile:
                self.config.write(configfile)
            # else: everything shiny
    # oauth

    def oauth_code(self, key):
        values = {
            'consumer_key': key,
            'redirect_uri': 'https://getpocket.com/connected_accounts'
        }

        response = self.request(values, request_url)
        code = response['code']
        message = ("Please open "
                   "https://getpocket.com/auth/authorize?request_token={0}"
                   "&redirect_uri=https://getpocket.com/connected_accounts"
                   " in your browser, authorize pocket-cli and run pocket-cli again.")
        print(message.format(code))
        return code

    def oauth_token(self, key, reqcode):
        values = {
            'consumer_key': key,
            'code': reqcode
        }

        resp_objects = self.request(values, authorize_url)
        # print(resp_objects)
        token = resp_objects['access_token']
        return token

    def request(self, values, target_url):
        data = urlencode(values)
        data = data.encode('UTF-8')
        req = Request(target_url, data)
        response = urlopen(req)
        # error handling
        if (response.status != 200):
            raise Exception(
                "Expected code 200, got {}".format(response.status))
        # replace with parse_qs?
        return dict(parse_qsl(response.read().decode('UTF-8')))


class PocketHandler:

    def __init__(self, auth, verbose, direct):
        self.verbose = verbose
        self.auth = auth
        self.direct = direct

    def create_values(self, optional):
        values = {'consumer_key': self.auth.key,
                  'access_token': self.auth.token}
        for key, value in optional.items():
            if key == 'url' and '@' in value:
                (values['url'], values['title']) = value.split('@', 1)
            else:
                values[key] = value

        return values

    def get_json(self, values, target_url):
        data = urlencode(values)
        data = data.encode('UTF-8')
        req = Request(target_url, data)
        response = urlopen(req)
        # error handling
        if (response.status != 200):
            raise Exception(
                "Expected code 200, got {}".format(response.status))
        return json.loads(response.read().decode('UTF-8'))

    def print_json(self, json):
        for item in sorted(json.values(), key=lambda item: item['sort_id']):
            try:
                title = item['resolved_title']
            except KeyError:
                title = '<no title found>'
            if self.direct:
                msg = "{}: {}"
                print(msg.format(title, item['given_url']))
            else:
                msg = "{}: https://getpocket.com/a/read/{}"
                print(msg.format(title, item['item_id']))

    def list_filtered(self, tag):
        if self.verbose:
            print("DEBUG: Filtering with tag '{}'.".format(tag))
        values = self.create_values({'state': 'all', 'tag': tag})
        json = self.get_json(values, get_url)['list']
        if not json:
            print("No results.")
        else:
            self.print_json(json)

    def list_unread(self):
        values = self.create_values({'state': 'unread'})
        json = self.get_json(values, get_url)['list']
        if not json:
            print("No results")
        else:
            self.print_json(json)

    def print_all_json(self):
        values = self.create_values({'state':'all'})
        json = self.get_json(values, get_url)['list']
        if not json:
            print("No results")
        else:
            print(json)

    def remove(self, item_id):
        # json hack from hell
        new_json = {
            'actions': '[{{"action":"delete","item_id":"{}"}}]'.format(item_id)
        }
        values = self.create_values(new_json)
        response = self.get_json(values, modify_url)
        return (response['status'] is not 0)

    def archive(self, item_id):
        # json hack from hell
        new_json = {
            'actions': '[{{"action":"archive","item_id":"{}"}}]'.format(item_id)
        }
        values = self.create_values(new_json)
        response = self.get_json(values, modify_url)
        return (response['status'] is not 0)

    def add_to_pocket(self, url):
        values = self.create_values({'url': url})
        response = self.get_json(values, add_url)
        return int(response['item']['item_id'])

    def add_with_tags(self, url, tag_list):
        tags = self.concatenate_tags(tag_list)
        values = self.create_values({'url': url, 'tags': tags})
        response = self.get_json(values, add_url)
        return int(response['item']['item_id'])

    def concatenate_tags(self, tag_list):
        return ','.join(tag_list)


def main():
    # init parser
    parser = argparse.ArgumentParser(description=('A command line tool'
                                     ' to manage your pocket items'))
    parser.add_argument('-a', '--add', metavar='URL', nargs='+',
                        help='add the URL(s) to your pocket, titles can'
                        ' optionally be specified in the format <url>@<title>')
    parser.add_argument('-t', '--tag', metavar='TAG', nargs='+',
                        help='add the TAG to the current'
                        ' item (specified by --add)')
    parser.add_argument('-u', '--unread',
                        help='show a list of your unread items',
                        action='store_true')
    parser.add_argument('-j', '--json',
                        help='show all items (json format)',
                        action='store_true')
    parser.add_argument('-f', '--filter', metavar='TAG', nargs=1,
                        help='show a list of all items with tag TAG')
    parser.add_argument('-r', '--remove', metavar='ID', nargs=1,
                        help='delete the item #ID from your pocket.')
    parser.add_argument('-c', '--archive', metavar='ID', nargs=1,
                        help='archive the item #ID from your pocket.')
    parser.add_argument('-v', '--verbose',
                        help='print totally helpful debug messages',
                        action='store_true')
    parser.add_argument('-d', '--direct',
                        help='get the actual URLs instead of pocket-URLs',
                        action='store_true')
    args = parser.parse_args()
    # parse arguments
    if not len(sys.argv) > 1:
        parser.print_help()
        exit(1)
    # we've got valid arguments, spawn stuff
    auth = AuthHandler(args.verbose)
    pocket = PocketHandler(auth, args.verbose, args.direct)

    # debug stuff
    if args.verbose:
        print("DEBUG: Using access token {}.".format(auth.token))
    # tag given, but no url to add the tag to
    if args.tag and not args.add:
        print("Currently --tag only works in conjuction with --add.")
    # direct option given but no option to fetch urls
    if args.direct and not (args.unread or args.filter):
        print('-d requires -f or -u in order to work', file=sys.stderr)

    # new item
    if args.add:
        if args.tag:
            for url in args.add:
                item_id = pocket.add_with_tags(url, args.tag)
                tags = pocket.concatenate_tags(args.tag)
                msg = "Added URL '{}' as item {}, with tag {}."
                print(msg.format(url, item_id, tags))
        else:
            for url in args.add:
                item_id = pocket.add_to_pocket(url)
                msg = "Added URL '{}' as item {}."
                print(msg.format(url, item_id))
    # list unread items
    if args.unread:
        pocket.list_unread()
    # list all (json format)
    if args.json:
        pocket.print_all_json()
    # filter by tag
    if args.filter:
        pocket.list_filtered(args.filter[0])
    if args.remove:
        pocket.remove(args.remove[0])
    if args.archive:
        pocket.archive(args.archive[0])

# call main method if not loaded as module
if __name__ == "__main__":
    main()
