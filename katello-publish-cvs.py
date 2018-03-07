#!/usr/bin/python

import json
import sys
import time
from datetime import datetime
import requests
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import logging
import ConfigParser as configparser
import os

# URL to your Satellite 6 server
URL = "https://localhost/"
# URL for the API to your deployed Satellite 6 server
#SAT_API = URL + "katello/api/v2/"
# Katello-specific API
#KATELLO_API = URL + "katello/api/"
POST_HEADERS = {'content-type': 'application/json'}
# Default credentials to login to Satellite 6
USERNAME = "admin"
PASSWORD = "admin"
# Ignore SSL for now
SSL_VERIFY = False
# Name of the organization to be either created or used
ORG_NAME = "Default Organization"
# Dictionary for Life Cycle Environments ID and name
ENVIRONMENTS = {}
# Search string to list currently running publish tasks
publish_tasks = "foreman_tasks/api/tasks?search=utf8=%E2%9C%93&search=label+%3D+Actions%3A%3AKatello%3A%3AContentView%3A%3APublish+and+state+%3D+running"
sync_tasks = "foreman_tasks/api/tasks?utf8=%E2%9C%93&per_page=1000&search=label+%3D+Actions%3A%3AKatello%3A%3ARepository%3A%3ASync+and+state+%3D+stopped+and+result+%3D+success"

def get_json(location):
    """
    Performs a GET using the passed URL location
    """
    try:
        r = requests.get(location, auth=(USERNAME, PASSWORD), verify=SSL_VERIFY)
    except Exception as e:
        log.critical(str(e))
        sys.exit(1)

    return r.json()


def post_json(location, json_data):
    """
    Performs a POST and passes the data to the URL location
    """
    try:
        result = requests.post(location,
                            data=json_data,
                            auth=(USERNAME, PASSWORD),
                            verify=SSL_VERIFY,
                            headers=POST_HEADERS)
    except Exception as e:
        log.critical(str(e))
        sys.exit(1)

    return result.json()

def put_json(location, json_data):
    """
    Performs a PUT and passes the data to the URL location
    """
    try:
        result = requests.put(location,
                            data=json_data,
                            auth=(USERNAME, PASSWORD),
                            verify=SSL_VERIFY,
                            headers=POST_HEADERS)
    except Exception as e:
        log.critical(str(e))
        sys.exit(1)

    return result.json()

def wait_for_publish(seconds):
    """
    Wait for all publishing tasks to terminate. Search string is:
    label = Actions::Katello::ContentView::Publish and state = running
    """
   
    count = 0 
    print "Waiting for publish tasks to finish..."
    
    # Make sure that publish tasks gets the chance to appear before looking for them
    time.sleep(2) 
    
    while get_json(URL + publish_tasks)["total"] != 0:
        time.sleep(seconds)
        count += 1

    print "Finished waiting after " + str(seconds * count) + " seconds"
    
def main():

    parser = argparse.ArgumentParser(description="Push new repositories to clients for given product")
    parser.add_argument("--cv-name", 
                        help="name of the content view containing the repository that has been updated. Specify ALL if you want to update all the CVs", 
                        required=True)
    parser.add_argument("-v", help="Debug logging", action='store_true')
    parser.add_argument("-c", "--config", help="Config File with katello addr and credentials", default="~/.config/katello-publish-cvs.ini")
    args = parser.parse_args()
    cv_name = args.cv_name
    
    # enable logging
    global log, URL, PASSWORD, ORG_NAME, SAT_API, KATELLO_API
    log = logging.getLogger(__name__)
    out_hdlr = logging.StreamHandler(sys.stdout)
    out_hdlr.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
    out_hdlr.setLevel(logging.DEBUG)
    log.addHandler(out_hdlr)
    if args.v:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)
        
    # Parsing Configuration and setting some defaults
    config = configparser.ConfigParser()
    config.read(os.path.expanduser(args.config))
    sections = config.sections()
    if len(sections) == 1:
        URL = config.get(sections[0], 'url')
        USERNAME = config.get(sections[0], 'username')
        PASSWORD = config.get(sections[0], 'password')
        ORG_NAME = config.get(sections[0], 'org_name')

    SAT_API = URL + "katello/api/v2/"
    KATELLO_API = URL + "katello/api/"
        
    # Check that organization exists and extract its ID
    org_json = get_json("{}organizations/{}".format(SAT_API, ORG_NAME))
    if org_json.get('error', None):
        log.error("ERROR: Inspect message")
        log.error(org_json)
        sys.exit(1)

    org_id = org_json["id"]
    log.debug('Organization "{}" has ID: {}'.format(ORG_NAME, org_id))

    # Fill dictionary of Lifecycle Environments as {name : id}
    envs_json = get_json("{}organizations/{}/environments?per_page=999".format(KATELLO_API, org_id))
    for env in envs_json["results"]:
        ENVIRONMENTS[env["name"]] = env["id"]

    log.debug("Lifecycle environments: {}".format(ENVIRONMENTS))
    
    # Get all non-composite CVs from the API
    if cv_name == 'ALL':
        cvs_json = get_json("{}organizations/{}/content_views?noncomposite=true&nondefault=true&name={}".format(SAT_API, org_id, cv_name))
    else:
        cvs_json = get_json("{}organizations/{}/content_views?noncomposite=true&nondefault=true".format(SAT_API, org_id))
   
    # Get all sync tasks
    sync_tasks_json = get_json(URL + sync_tasks)

    # Publish new versions of the CVs that have new content in the underlying repos
    published_cv_ids = []
    searched_cv_ids = []
    for cv in cvs_json["results"]:
        searched_cv_ids.append(cv["id"])
        last_published = cv["last_published"]
        if last_published is None:
            last_published = "2000-01-01 00:00:00 UTC"
        last_published = datetime.strptime(last_published, '%Y-%m-%d  %X %Z')

        need_publish = False
        for repo in cv["repositories"]:
            for task in sync_tasks_json["results"]:
                if task["input"]["repository"]["id"] == repo["id"]:
                    ended_at = datetime.strptime(task["ended_at"], '%Y-%m-%dT%H:%M:%S.000Z')

                    if ended_at > last_published and task["input"]["contents_changed"]:
                        log.info("A sync task for repo \"{}\" downloaded new content and ended after {} was published last time".format(repo['name'], cv['name']))
                        need_publish = True

        if need_publish:
            log.info("Publish {} because some of its content has changed".format(cv["name"]))
            post_json("{}content_views/{}/publish".format(KATELLO_API, cv['id']), json.dumps({"description": "Automatic publish over API"}))
            published_cv_ids.append(cv["id"])
        else:
            log.debug("{} doesn't need to be published".format(cv['name']))
            
    wait_for_publish(10)

    # Get all CCVs from the API 
    ccvs_json = get_json("{}organizations/{}/content_views?composite=true".format(SAT_API, org_id))
    
    # Publish a new version of all CCs that contain any of the published CVs
    ccv_ids_to_promote = []
    for ccv in ccvs_json["results"]:
        new_component_ids = []
        skip = True
        for component in ccv["components"]:
            if component["content_view_id"] in searched_cv_ids:
                skip = False
            cv_json = get_json("{}content_views/{}".format(KATELLO_API,component["content_view"]["id"]))
            for version in cv_json["versions"]:
                if ENVIRONMENTS["Library"] in version["environment_ids"]:
                    new_component_ids.append(version["id"])
        if skip:
            continue            
        print "Update " + ccv["name"] + " with new component IDs: " + str(new_component_ids)
        put_json(KATELLO_API + "content_views/" + str(ccv["id"]), json.dumps({"component_ids": new_component_ids}))
        
        print "Publish new version of " + ccv["name"]
        post_json(KATELLO_API + "content_views/" + str(ccv["id"]) + "/publish", json.dumps({"description": "Automatic publish over API"}))

        # Get the ID of the version in Library 
        version_in_library_id = get_json("{}content_views/{}/content_view_versions?environment_id={}".format(KATELLO_API, ccv['id'], ENVIRONMENTS["Library"]))["results"][0]["id"]
        ccv_ids_to_promote.append(str(version_in_library_id))

    wait_for_publish(10)
    
    print "Promote all effected CCVs to Sviluppo environment"
    for ccv_id in ccv_ids_to_promote:
        post_json(KATELLO_API + "content_view_versions/" + str(ccv_id) + "/promote", json.dumps({"environment_id": ENVIRONMENTS["Sviluppo"]}))


if __name__ == "__main__":
    main()
