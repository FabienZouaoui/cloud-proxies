#!/usr/bin/env python3

import requests, subprocess, gc, argparse, signal, sys, traceback, logging, json, base64
from requests.auth import HTTPBasicAuth
from time import sleep
from os import chmod, kill, environ
from datetime import tzinfo, timedelta, datetime
from jinja2 import Environment, FileSystemLoader


class UTC(tzinfo):
    def utcoffset(self, dt):
        return timedelta(0)
    def tzname(self, dt):
        return "UTC"
    def dst(self, dt):
        return timedelta(0)


class Oxylabs:
    def __init__(self, username, password, list_id):
        self.username = username
        self.password = password
        self.list_id  = list_id
        self.url_base = 'https://api.oxylabs.io/v1'
        self.headers = {'content-type': 'application/json' }

    def instances(self, region):
        instances = []
        r = requests.get(self.url_base + '/proxies/lists/' + self.list_id, headers=self.headers, 
            auth=HTTPBasicAuth(self.username, self.password))
        for instance in r.json():
            if instance['country'] == region:
                instances.append(instance)
        return instances


class PProxy:
    def __init__(self, listen="socks5://:8000/", remote="httponly://localhost:8001"):
        self.process = subprocess.Popen([
            'pproxy', '-l', listen, '-r', remote
        ])

    def stop(self):
        try:
            self.process.terminate()
        except:
            True
        self.process = None
        
class Haproxy:
    def __init__(self, instances, templates_dir, haproxy_template, provider, base64auth, configFile='/dev/shm/haproxy.cfg'):
        self.dir        = templates_dir
        self.template   = haproxy_template
        self.provider   = provider
        self.base64auth = base64auth
        self.config     = configFile
        self.pid        = str()
        self.pidfile    = '/run/haproxy.pid'
        self.old_pids   = []

        self.update_conf(instances)

        subprocess.run([
            'haproxy', '-q', '-p', self.pidfile, '-f', self.config
        ])
        sleep(2)
        self.pid = self.get_pid()

    def update_conf(self, instances, reload=False):
        self.env   = Environment(loader=FileSystemLoader(self.dir), trim_blocks=True)
        self.templ = self.env.get_template(self.template)
        output     = self.templ.render(instances=instances, provider=self.provider, base64auth=self.base64auth) 
        with open(self.config, 'w') as f:
            f.write(output)
        if reload:
            self.reload()

    def get_pid(self):
        with open(self.pidfile, 'r') as file:
            pid = file.read().rstrip()
        return pid
        
    def reload(self):
        subprocess.run([
            'haproxy', '-q', '-f', self.config,
            '-p', self.pidfile, '-sf', self.pid
        ])
        self.old_pids.append(self.pid)
        self.pid = self.get_pid()

    def stop(self):
        self.old_pids.append(self.pid)
        for pid in [int(i) for i in self.old_pids]:
            try:
                kill(pid, signal.SIGUSR1)
            except:
                True

def sigterm_handler(_signo, _stack_frame):
    logging.info("Sigterm signal received. Stopping haproxy")
    sys.exit(0)

def main(loop_time, wait_time, provider, username, password, list_id, region, templates_dir, haproxy_template):
    instances         = [] 
    updated_instances = [] 
    userpass          = username + ":" + password
    base64auth        = base64.b64encode(userpass.encode()).decode()
    pproxy            = PProxy()
    haproxy           = Haproxy(instances, templates_dir, haproxy_template, provider, base64auth)

    if provider == 'oxylabs':
        cloud = Oxylabs(username, password, list_id)

    signal.signal(signal.SIGTERM, sigterm_handler)
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)

    logging.info("Getting proxy instances")
    
    instances = cloud.instances(region)
    haproxy.update_conf(instances, reload=True)
    
    logging.info("Starting main loop")
    try:
        while True:
            sleep(loop_time)
            gc.collect()

            updated_instances = cloud.instances(region)
            updated = False

            for instance in updated_instances:
                if instance not in instances:
                    logging.info("New instance found (%s). Updating conf and relading haproxy", instance['ip'])
                    haproxy.update_conf(updated_instances, reload=True)
                    instances = updated_instances
                    updated = True
                    break

            if updated:
                continue

            for instance in instances:
                if instance not in updated_instances:
                    logging.info("Obsolete instance found (%s). Updating conf and relading haproxy", instance['ip'])
                    haproxy.update_conf(updated_instances, reload=True)
                    instances = updated_instances
                    continue

    finally:
        haproxy.stop()
        pproxy.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--templates_dir",       help="Directory where are stored jinja2 templates", required=True)
    parser.add_argument("--haproxy_template",    help="HAProxy template used by jinja2", required=True)

    parser.add_argument("--provider",            help="Cloud provider", choices=['oxylabs'], required=True)
    parser.add_argument("--username",            help="username to connect to api and proxies", required=True)
    parser.add_argument("--password",            help="password to connect to api and proxies", required=True)
    parser.add_argument("--list_id",             help="proxy list id", required=True)
    parser.add_argument("--region",              help="region where to launch instances", required=True)

    parser.add_argument("--loop_time",           help="Time to wait between two loops iterations", default=60, type=int)
    parser.add_argument("--wait_time",           help="Time to wait before reload haproxy conf or deleting ssh tunnels", default=60, type=int)

    args = parser.parse_args()

    main(
        args.loop_time,
        args.wait_time,
        args.provider,
        args.username,
        args.password,
        args.list_id,
        args.region,
        args.templates_dir,
        args.haproxy_template,
    )
