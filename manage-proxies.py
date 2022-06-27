#!/usr/bin/env python3

import boto3, requests, subprocess, gc, argparse, signal, sys, traceback, logging, json, random, string, traceback
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


class Vultr:
    def __init__(self, api_key):
        self.api_key = api_key
        self.url_base = 'https://api.vultr.com/v2'
        self.headers = {'content-type': 'application/json', 'Authorization': 'Bearer ' + self.api_key}

    def instances(self, region):
        r = requests.get(self.url_base + '/instances', params={ 'tag': region}, headers=self.headers)
        try:
            return r.json()['instances']
        except:
            logging.error("Error while retrieving instances")
            print(f"status code: {r.status_code}")
            print(r.text)
            sys.exit(1)

    def get(self, instance_id):
        r = requests.get(self.url_base + '/instances/' + instance_id, headers=self.headers)
        try:
            return r.json()['instance']
        except:
            logging.error("Error while fetching instance %s", instance_id)
            print(f"status code: {r.status_code}")
            print(r.text)
            sys.exit(1)

    def get_id(self, cloud_instance):
        return cloud_instance['id']

    def get_ip(self, cloud_instance):
        return cloud_instance['main_ip']

    def get_status(self, cloud_instance):
        return cloud_instance['server_status']

    def get_created_date(self, cloud_instance):
        return cloud_instance['date_created']

    def delete(self, instance_id):
        r = requests.delete(self.url_base + '/instances/' + instance_id, headers=self.headers)
        return True

    def create_instance(self, region, plan, os_id, sshkey_id, hostname):
        payload = { 'region': region, 'plan': plan, 'os_id': int(os_id), 'sshkey_id': [int(sshkey_id)], 'tag': region, 'hostname': hostname }
        r = requests.post(self.url_base + '/instances', headers=self.headers, data=json.dumps(payload))
        try:
            return r.json()['instance']
        except:
            logging.error("Error while creating instance")
            print(f"status code: {r.status_code}")
            print(r.text)
            sys.exit(1)


class DigitalOcean:
    def __init__(self, api_key):
        self.api_key = api_key
        self.url_base = 'https://api.digitalocean.com/v2'
        self.headers = {'content-type': 'application/json', 'Authorization': 'Bearer ' + self.api_key}

    def instances(self, region):
        r = requests.get(self.url_base + '/droplets', params={'tag_name': region, 'per_page': 200}, headers=self.headers)
        try:
            return r.json()['droplets']
        except:
            logging.error("Error while retrieving instances")
            print(f"status code: {r.status_code}")
            print(r.text)
            sys.exit(1)

    def get(self, instance_id):
        r = requests.get(self.url_base + '/droplets/' + instance_id, headers=self.headers)
        if r.status_code in [500, 503, 504, 530, 520, 524, 429, 409]:
            logging.warning("Status code %d received when retrieving instance %s with message: %s", r.status_code, instance_id, r.text)
            return None
        if r.status_code == 404:
            logging.warning("Status code %d received when retrieving instance %s with message: %s", r.status_code, instance_id, r.text)
            return {'status': 'deleted'}
        try:
            return r.json()['droplet']
        except:
            logging.error("Error while fetching instance %s", instance_id)
            logging.error("status code: %s", r.status_code)
            print(r.text)
            sys.exit(1)

    def get_id(self, cloud_instance):
        return str(cloud_instance['id'])

    def get_ip(self, cloud_instance):
        try:
            for network in cloud_instance['networks']['v4']:
                if network['type'] == "public":
                    return network['ip_address']
            return None
        except:
            return None

    def get_status(self, cloud_instance):
        if cloud_instance['status'] == 'active':
            return 'ok'
        return cloud_instance['status']

    def get_created_date(self, cloud_instance):
        return cloud_instance['created_at'].replace('Z', '')

    def delete(self, instance_id):
        r = requests.delete(self.url_base + '/droplets/' + instance_id, headers=self.headers)
        return True

    def create_instance(self, region, size, image, ssh_keys, name):
        payload = { 'region': region, 'size': size, 'image': image, 'ssh_keys': [ssh_keys], 'tags': [region], 'name': name, 'with_droplet_agent': False , 'ipv6': False}
        r = requests.post(self.url_base + '/droplets', headers=self.headers, data=json.dumps(payload))
        if r.status_code != 202:
            logging.warning("Status code %d received while creating instance with message %s: ", r.status_code, r.text)
            return None
        sleep(1)

        try:
            if self.wait_for_action(r.json()['links']['actions'][0]['id']):
                return r.json()['droplet']
            return False
        except:
            logging.error("Error while creating instance")
            logging.error("status code: %s", r.status_code)
            print(r.text)
            sys.exit(1)

    def wait_for_action(self, action_id):
        try:
            r = requests.get(self.url_base + '/actions/' + str(action_id), headers=self.headers)
        except Exception as err:
            traceback.print_tb(err.__traceback__)
            print(r.text)
            logging.error("Erreur while querying action %d. Sleeping 10 seconds and continue anyway", action_id)
            sleep(10)
            return False

        if r.status_code != 200:
            logging.error("HTTP code %d returned when querying action %d. Sleeping 10 seconds and continue anyway", r.status_code, action_id)
            sleep(10)
            return False

        try:
            while r.json()['action']['status'] == "in-progress":
                logging.info("Waiting action %d to finish", action_id)
                sleep(5)
                r = requests.get(self.url_base + '/actions/' + str(action_id), headers=self.headers)
        except Exception as err:
            traceback.print_tb(err.__traceback__)
            print(r.text)
            logging.error("Error while refreshing action %d. Sleeping 10 seconds and continue anyway", action_id)
            sleep(10)
            return False

        if r.json()['action']['status'] == "completed":
            logging.info("Action %d completed", action_id)
            return True
        logging.error("Action %d terminated with an unexpected status: %s", action_id, r.json()['action']['status'])
        #sys.exit(1)
        return False


class AWS:
    def __init__(self):
        self.ec2_client         = boto3.client('ec2')
        self.ec2_resource       = boto3.resource('ec2')

    def instances(self, region):
        instances = []
        for instance in self.ec2_client.describe_instances()['Reservations']:
            instances.append(instance['Instances'][0])
        return instances

    def get(self, instance_id):
        return self.ec2_client.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]

    def get_id(self, cloud_instance):
        return cloud_instance['InstanceId']

    def get_ip(self, cloud_instance):
        try:
            ip = cloud_instance['PublicIpAddress']
            return ip
        except:
            return None

    def get_status(self, cloud_instance):
        if cloud_instance['State']['Name'] == 'running':
            return 'ok'
        return cloud_instance['State']['Name']

    def get_created_date(self, cloud_instance):
        return datetime.isoformat(cloud_instance['LaunchTime'])

    def delete(self, instance_id):
        self.ec2_client.stop_instances(InstanceIds=[instance_id])
        self.ec2_client.terminate_instances(InstanceIds=[instance_id])
        return True

    def create_instance(self, sec_group, ec2_type, ec2_img, ami_keyname, name):
        try:
            created = self.ec2_resource.create_instances(
                ImageId=ec2_img,
                KeyName=ami_keyname,
                SecurityGroupIds=[
                    sec_group # This arg have a different meaning for aws instances
                ],
                InstanceType=ec2_type,
                MinCount=1, MaxCount=1
            )
            sleep(2)
            return self.ec2_client.describe_instances(InstanceIds=[created[0].id])['Reservations'][0]['Instances'][0]
        except Exception as err:
            logging.error("Error while creating aws Instance: %s", created[0].id)
            traceback.print_tb(err.__traceback__)
            sys.exit(1)


class Kamatera:
    def __init__(self, client_id, api_key):
        self.client_id = client_id
        self.api_key   = api_key
        self.url_base  = 'https://console.kamatera.com/service'
        self.headers = {'Content-type': 'application/x-www-form-urlencoded', 'AuthClientId': self.client_id, 'AuthSecret': self.api_key}

    def instances(self, region):
        instances = []
        r = requests.get(self.url_base + '/servers', headers=self.headers)
        try:
            for instance in r.json():
                if instance['datacenter'] == region:
                    instances.append(self.get(instance['id']))
            return instances
        except:
            logging.error("Error while retrieving instances")
            print(f"status code: {r.status_code}")
            print(r.text)
            sys.exit(1)

    def get(self, instance_id):
        r = requests.get(self.url_base + '/server/' + instance_id, headers=self.headers)
        try:
            return r.json()
        except:
            logging.error("Error while fetching instance %s", instance_id)
            print(f"status code: {r.status_code}")
            print(r.text)
            sys.exit(1)

    def get_id(self, cloud_instance):
        return cloud_instance['id']

    def get_ip(self, cloud_instance):
        try:
            ip = cloud_instance['networks'][0]['ips'][0]
            return ip
        except:
            logging.warning("Unable to retrieve ip for instance %s", self.get_id(cloud_instance))
            return None

    def get_status(self, cloud_instance):
        try:
            if cloud_instance['power'] == 'on':
                return 'ok'
        except:
            cloud_instance['status'] = 'error'
        return cloud_instance['status']

    def get_created_date(self, cloud_instance):
        try:
            index = clud_instance['name'].rindex('_') # They can add _something to the name
        except:
            index = None
        return datetime.fromtimestamp(float(cloud_instance['name'][:index])).isoformat()

    def delete(self, instance_id):
        payload = {'confirm': 1, 'force': 1}
        r = requests.delete(self.url_base + '/server/' + instance_id + '/terminate',
             data=payload,
             headers=self.headers)
        sleep(2)
        self.wait_for_command(r.text)
        return True

    def create_instance(self, region, cpu_ram_disk, image, ssh_keys, name):
        #cpu = '1A'
        #ram = 512
        #disk_size_0 = 10
        payload = {
            'datacenter': region,
            'cpu': cpu_ram_disk.split('-')[0],
            'ram': int(cpu_ram_disk.split('-')[1]),
            'disk_size_0': int(cpu_ram_disk.split('-')[2]),
            'disk_src_0': image,
            'name': name,
            'password': ''.join(random.sample(string.ascii_letters+string.digits, 17)),
            'power': 1,
            'billing': 'hourly',
            'network_name_0': 'wan'
        }
        r = requests.post(self.url_base + '/server', headers=self.headers, data=payload)

        #try:
        #    self.wait_for_command(str(r.json()[0]))
        #except:
        #    logging.error("Error while retireving command status")
        #    print(r.json())
        #    sys.exit(1)
        sleep(2)
        self.wait_for_command(str(r.json()[0]), 10)
        sleep(2)
        return self.search_by_name(self, region, name)

    def search_by_name(self, region, name):
        result = None
        r = requests.get(self.url_base + '/servers', headers=self.headers)
        for instance in r.json():
            if instance['datacenter'] != region:
                continue
            try:
                index = instance.rindex('_') # They can add _something to the name
            except:
                index = None
            if instance['name'][:index] == name:
                result = instance
                break
        return result

    def wait_for_command(self, command_id, loop_time=2):
        r = requests.get(self.url_base + '/queue/' + command_id, headers=self.headers)
        try:
            while r.json()['status'] not in ['complete', 'error', 'cancelled']:
                logging.info(f"Waiting for command %s to complete", command_id)
                sleep(loop_time)
                r = requests.get(self.url_base + '/queue/' + command_id, headers=self.headers)
        except:
            logging.error("Unable to retrieve queued command %s", command_id)
            print(r.json())
            traceback.print_stack()
            raise Exception('Unable to retrieve queued command')

        logging.info("Command terminated with status: %s", r.json()['status'])
        if r.json()['status'] != 'complete':
            print(r.json())
            sys.exit(1)
        return r


class Linode:
    def __init__(self, api_key, tag):
        self.api_key = api_key
        self.url_base = 'https://api.linode.com/v4'
        self.headers = {'content-type': 'application/json', 'Authorization': 'Bearer ' + self.api_key}
        self.tag = tag

    def instances(self, region):
        instances = []
        r = requests.get(self.url_base + '/linode/instances', headers=self.headers)
        try:
            for instance in r.json()['data']:
                #if instance['region'] == region:
                if instance['region'] == region and (not self.tag or self.tag in instance['tags']):
                    instances.append(instance)
            return instances
        except:
            logging.error("Error while retrieving instances")
            logging.error("status code: %s", r.status_code)
            print(r.text)
            sys.exit(1)

    def get(self, instance_id):
        r = requests.get(self.url_base + '/linode/instances/' + instance_id, headers=self.headers)
        if r.status_code == 404:
            logging.warning("Status code %d received when retrieving instance %s with message: %s", r.status_code, instance_id, r.text)
            logging.warning("Marking instance as deleted")
            return {'status': 'deleted'}

        if r.status_code != 200:
            logging.warning("Status code %d received when retrieving instance %s with message: %s", r.status_code, instance_id, r.text)
            return None

        try:
            return r.json()
        except:
            logging.error("Error while fetching instance %s", instance_id)
            logging.error("status code: %s", r.status_code)
            print(r.text)
            sys.exit(1)

    def get_id(self, cloud_instance):
        return str(cloud_instance['id'])

    def get_ip(self, cloud_instance):
        try:
            return cloud_instance['ipv4'][0]
        except:
            return None

    def get_status(self, cloud_instance):
        try:
            if cloud_instance['status'] == 'running':
                return 'ok'
            return cloud_instance['status']
        except:
            logging.error("Error while extracting status from cloud instance")
            logging.error(cloud_instance)
            sys.exit(1)

    def get_created_date(self, cloud_instance):
        try:
            return cloud_instance['created']
        except:
            print(cloud_instance)
            sys.exit(1)

    def delete(self, instance_id):
        r = requests.delete(self.url_base + '/linode/instances/' + instance_id, headers=self.headers)
        return True

    def create_instance(self, region, linode_type, image, ssh_keys, name):
        payload = { 'region': region,
            'type': linode_type,
            'image': image,
            'authorized_keys': [ssh_keys],
            'private_ip': False,
            'root_pass': ''.join(random.sample(string.ascii_letters+string.digits, 17)),
        }
        if self.tag:
            payload['tags'] = [self.tag]
        r = requests.post(self.url_base + '/linode/instances', headers=self.headers, data=json.dumps(payload))
        if r.status_code != 200:
            logging.warning("Status code %d received while creating instance with message %s: ", r.status_code, r.text)
            return None
        try:
            instance = r.json()
        except:
            logging.error("Error while creating instance")
            print(f"status code: {r.status_code}")
            print(r.text)
            sys.exit(1)

        sleep(1)
        updated_instance   = self.update(self.get_id(instance))
        if updated_instance:
            instance = updated_instance
        instance['status'] = 'provisioning'
        return instance

    def update(self, instance_id):
        payload = {'alerts': {'network_in': 100, 'network_out': 100, 'transfer_quota': 200}}
        r = requests.put(self.url_base + '/linode/instances/' + instance_id, headers=self.headers, data=json.dumps(payload))
        try:
            instance = r.json()
            return instance
        except:
            logging.error("Error while updating instance")
            logging.error("status code: %s", r.status_code)
            print(r.json())
            return None


class Upcloud:
    def __init__(self, api_key):
        self.api_key = api_key
        self.url_base = 'https://api.upcloud.com/1.3'
        self.headers = {'content-type': 'application/json', 'Authorization': 'Basic ' + self.api_key}

    def instances(self, region):
        instances = []
        r = requests.get(self.url_base + '/server', headers=self.headers)
        try:
            for instance in r.json()['servers']['server']:
                if instance['zone'] == region:
                    instances.append(self.get(instance['uuid']))
            return instances
        except:
            logging.error("Error while retrieving instances")
            print(f"status code: {r.status_code}")
            print(r.text)
            sys.exit(1)

    def get(self, instance_id):
        r = requests.get(self.url_base + '/server/' + instance_id, headers=self.headers)
        try:
            return r.json()['server']
        except:
            logging.error("Error while fetching instance %s", instance_id)
            print(f"status code: {r.status_code}")
            print(r.text)
            sys.exit(1)

    def get_id(self, cloud_instance):
        return cloud_instance['uuid']

    def get_ip(self, cloud_instance):
        try:
            return cloud_instance['networking']['interfaces']['interface'][0]['ip_addresses']['ip_address'][0]['address']
        except:
            return None

    def get_status(self, cloud_instance):
        if cloud_instance['state'] == 'started':
            return 'ok'
        return cloud_instance['state']

    def get_created_date(self, cloud_instance):
        return datetime.fromtimestamp(float(cloud_instance['hostname'])).isoformat()

    def delete(self, instance_id):
        timeout = 10
        self.stop(instance_id, timeout)
        sleep(timeout)
        params = {'storages': '0', 'backups': 'delete'}
        r = requests.delete(self.url_base + '/server/' + instance_id + '/delete',
             params=params,
             headers=self.headers)
        return True

    def stop(self, instance_id, timeout):
        payload = {'stop_server': {'stop_type': 'hard', 'timeout': str(timeout)}}
        r = requests.post(self.url_base + '/server/' + instance_id + '/stop',
             data=payload,
             headers=self.headers)

    def create_instance(self, zone, plan, image, ssh_key, name):
        payload = {
            'server': {
                'zone': zone,
                'title': 'My proxy server',
                'hostname': name,
                'plan': plan,
                'networking': {
                    'interfaces': {
                        'interface': [
                            {
                                'ip_addresses': {
                                    'ip_address': [
                                        {'family': 'IPv4'}
                                    ]
                                },
                                'type': 'public'
                            }
                        ]
                    }
                },
                'storage_devices': {
                    'storage_device': [
                        {
                            'title': 'My storage device',
                            'action': 'clone',
                            'storage': image,
                            'size': 10,
                        }
                    ]
                },
                'login_user': {
                    'username': 'root',
                    'ssh_keys': {
                        'ssh_key': [
                            ssh_key
                        ]
                    }
                }
            }
        }
        r = requests.post(self.url_base + '/server', headers=self.headers, data=json.dumps(payload))
        if r.status_code != 202:
            print(f"status code: {r.status_code}")
            print(r.json())
            sys.exit(1)
        try:
            return r.json()
        except:
            logging.error("Error while creating instance")
            print(f"status code: {r.status_code}")
            print(r.text)
            sys.exit(1)


class Node:
    def __init__(self, cloud, cloud_instance, ports, user):
        self.tunnels            = list()
        self.cloud              = cloud
        self.cloud_instance     = cloud_instance
        self.cloud_instance_id  = None
        self.ports              = ports
        self.available_ports    = self.ports.copy()
        self.user               = user

        self.consolidate()

    def get_cloud_instance_id(self):
        if not self.cloud_instance_id:
            self.cloud_instance_id = self.cloud.get_id(self.cloud_instance)
        return self.cloud_instance_id

    def consolidate(self):
        self.status = self.cloud.get_status(self.cloud_instance)
        self.ip     = self.cloud.get_ip(self.cloud_instance)
        if not self.ip and self.status != "terminated":
            logging.info("Modifying intance %s status from %s to installingbooting", self.get_cloud_instance_id(), self.status)
            self.status = 'installingbooting'
        self.date   = self.cloud.get_created_date(self.cloud_instance)
        self.ts     = datetime.fromisoformat(self.date).timestamp()
        
    def update(self):
        updated_instance = self.cloud.get(self.get_cloud_instance_id())
        if not updated_instance:
            logging.info("Cannot update instance, reusing old data as workaround")
            return False
        if updated_instance['status'] == "deleted":
            logging.info("Modifying intance %s status from %s to deleted", self.get_cloud_instance_id(), self.status)
            self.status = updated_instance['status']
            return False
        self.cloud_instance = updated_instance
        self.consolidate()

    def create_ssh_tunnels(self, keyfile):
        chmod(keyfile, 0o400)
        for port in self.available_ports.copy():
            if len(self.tunnels) >= len(self.ports):
                logging.info("Instance %s already has the required tunnels number", self.get_cloud_instance_id())
                break

            logging.info("Adding tunnel to port %d to instance %s", port, self.get_cloud_instance_id())
            self.tunnels.append(
                {
                    'port': port,
                    'process': subprocess.Popen([
                        'ssh', '-N', '-q',
                        '-o', 'StrictHostKeyChecking=no',
                        '-o', 'UserKnownHostsFile=/dev/null',
                        '-o', 'Compression=no',
                        '-o', 'Ciphers=aes128-ctr',
                        '-i', keyfile,
                        '-D', '127.0.0.1:'+str(port),
                        '-l', self.user,
                        self.ip
                    ])
                }
            )
            self.available_ports.remove(port)

    def stop_ssh_tunnel(self, tunnel):
        logging.info("Terminating process with pid %s", tunnel['process'].pid)
        tunnel['process'].terminate()
        self.tunnels.remove(tunnel)
        logging.info("Re-adding port %d to the pool", tunnel['port'])
        self.available_ports.append(tunnel['port'])

    def stop_all_ssh_tunnels(self):
        for tunnel in self.tunnels.copy():
            self.stop_ssh_tunnel(tunnel)
        self.tunnels.clear()
        self.available_ports = self.ports.copy()
        return self.ports

    def terminate(self):
        self.cloud.delete(self.get_cloud_instance_id())
        self.cloud = None
        self.cloud_instance = None
        return self.stop_all_ssh_tunnels()

class Haproxy:
    def __init__(self, running_instances, templates_dir, haproxy_template, provider, configFile='/dev/shm/haproxy.cfg'):
        self.dir      = templates_dir
        self.template = haproxy_template
        self.provider = provider
        self.config   = configFile
        self.pid      = str()
        self.pidfile  = '/run/haproxy.pid'
        self.old_pids = []

        self.update_conf(running_instances)

        subprocess.run([
            'haproxy', '-q', '-p', self.pidfile, '-f', self.config
        ])
        sleep(2)
        self.pid = self.get_pid()

    def update_conf(self, running_instances, reload=False):
        self.env   = Environment(loader=FileSystemLoader(self.dir), trim_blocks=True)
        self.templ = self.env.get_template(self.template)
        output     = self.templ.render(instances=running_instances, provider=self.provider) 
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
    logging.info("Sigterm signal received. Stopping ssh tunnels and haproxy")
    sys.exit(0)

def main(loop_time, wait_time, keyfile, provider, client_id, api_key, os_id, plan, region, sshkey_id, tag, templates_dir, haproxy_template, instances_ttl, tunnels_by_instance, required_instances=1):
    non_running_instances = set()
    running_instances     = set()
    pending_instances     = set()
    avail_ports           = list(range(8080, 8980))
    tunnels_are_ok        = False
    haproxy               = Haproxy(running_instances, templates_dir, haproxy_template, provider)
    tunnels_to_remove     = []
    ssh_user              = 'root'

    if provider == 'vultr':
        cloud = Vultr(api_key)
    elif provider == 'digitalocean':
        cloud = DigitalOcean(api_key)
    elif provider == 'aws':
        if not 'AWS_SHARED_CREDENTIALS_FILE' in environ:
            logging.error("AWS_SHARED_CREDENTIALS_FILE env var is not set")
            sys.exit(1)
        ssh_user = 'ec2-user'
        cloud = AWS()
    elif provider == 'kamatera':
        if not client_id:
            logging.error("--client_id is required when provider is kamatera")
            sys.exit(1)
        cloud = Kamatera(client_id, api_key)
    elif provider == 'linode':
        cloud = Linode(api_key, tag)
    elif provider == 'upcloud':
        cloud = Upcloud(api_key)

    signal.signal(signal.SIGTERM, sigterm_handler)
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)

    logging.info("Getting previous cloud instances")
    try:
        # Check for existing instances on startup
        for cloud_instance in cloud.instances(region):
            instance = Node(cloud, cloud_instance, [avail_ports.pop(0) for x in range(tunnels_by_instance)], ssh_user)
            logging.info("Retrieved instance with id %s, ip %s and status %s", instance.get_cloud_instance_id(), instance.ip, instance.status)

            if instance.status == 'terminated':
                logging.info("Skipping instance %s", instance.cloud_instance_id)
                continue
            if instance.status != 'ok':
                pending_instances.add(instance)
                continue
    
            running_instances.add(instance)
            instance.create_ssh_tunnels(keyfile)
            continue
    
        haproxy.update_conf(running_instances, reload=True)
    
        logging.info("Starting main loop")
        while True:
            # Update instances status
            for instance in running_instances.union(pending_instances):
                instance.update()
    
            # Set previously pending instances as running if needed
            started = filter(lambda i: i.status == 'ok', pending_instances)
            for instance in started:
                logging.info("Instance %s with ip address %s has changed status to %s. Sleeping %s seconds before creating tunnels and reload haproxy",
                    instance.get_cloud_instance_id(), instance.ip, instance.status, wait_time)
                sleep(wait_time)
                instance.create_ssh_tunnels(keyfile)
                sleep(1)
                running_instances.add(instance)
                haproxy.update_conf(running_instances, reload=True)
                logging.info("Haproxy reloaded")
            pending_instances.difference_update(running_instances)
    
            # Check status for running instances
            for instance in running_instances:
                if instance.status != 'ok':
                    logging.error(
                        'Warning, Instance {} is in the {} state. Removing it from running nodes'.format(
                            instance.get_cloud_instance_id(),
                            instance.status
                        )
                    )
                    avail_ports.extend(instance.terminate())
                    non_running_instances.add(instance)
                    continue

                for tunnel in instance.tunnels:
                    tunnel['process'].poll()
                    if tunnel['process'].returncode is not None:
                        tunnels_to_remove.append(tunnel)

                for tunnel in tunnels_to_remove:
                    instance.stop_ssh_tunnel(tunnel)

                if tunnels_to_remove:
                    instance.create_ssh_tunnels(keyfile)
                    tunnels_to_remove.clear()

            running_instances.difference_update(non_running_instances)
            if non_running_instances:
                haproxy.update_conf(running_instances, reload=True)
                non_running_instances = set()
    
            # Checking that we don't have any "rogue" instances
            dst_instances = []
            try:
                for dst_instance in cloud.instances(region):
                    if cloud.get_status(dst_instance) in ['ok', 'installingbooting', 'new', 'pending', 'off', 'booting', 'provisioning']:
                        dst_instances.append(dst_instance)
                        continue
                    if cloud.get_status(dst_instance) not in ['terminated']:
                        logging.info("Ignoring instance %s with status %s while checking constitency", cloud.get_id(dst_instance), cloud.get_status(dst_instance))
            except:
                logging.error("Unable to get cloud instance list for verification. I'll try next time")

            if len(dst_instances) > len(running_instances) + len(pending_instances):
                logging.error("Something nasty has happened. More instances retrieved than what we have locally")
                for dst_instance in dst_instances:
                    dst_id = cloud.get_id(dst_instance)
                    found = False
                    for local_node in running_instances.union(pending_instances):
                        if local_node.get_cloud_instance_id() == dst_id:
                            found = True
                            break
                    if found:
                        continue

                    logging.warning("I should have added instance %s to pending_instances and keep going", dst_id)
                    #pending_instances.add(dst_instance)
                break # Exiting main loop !

            # Delete older instance if TTL is reached and we have enough instances
            if len(running_instances) + len(pending_instances) > required_instances:
                oldest_instance = min(running_instances.union(pending_instances), key=lambda i: i.ts)
                if (datetime.utcnow().timestamp() - oldest_instance.ts) > instances_ttl:
                    logging.info("Removing oldest (created at %s UTC) instance %s with ip %s from config and reload haproxy", oldest_instance.date, oldest_instance.get_cloud_instance_id(), oldest_instance.ip)
                    running_instances.discard(oldest_instance)
                    pending_instances.discard(oldest_instance)
                    haproxy.update_conf(running_instances, reload=True)
                    logging.info("Haproxy reloaded")
                    logging.info("Sleeping %s seconds before removing ssh tunnels and deleting instance %s", wait_time, oldest_instance.get_cloud_instance_id())
                    sleep(wait_time)
                    avail_ports.extend(oldest_instance.terminate())
    
            # Create new instance if needed
            if len(running_instances) + len(pending_instances) <= required_instances:
                logging.info("Creating new instance to reach targeted number")
                try:
                    created = cloud.create_instance(region, plan, os_id, sshkey_id, str(datetime.utcnow().timestamp()))
                    if created:
                        pending_instances.add(Node(cloud, created, [avail_ports.pop(0) for x in range(tunnels_by_instance)], ssh_user))
                        logging.info("instance correctly added: %s", cloud.get_id(created))

                except Exception as err:
                    logging.error("Error while creating cloud Instance")
                    traceback.print_tb(err.__traceback__)
                    sys.exit(1)
 
            sleep(loop_time)
            gc.collect()
    finally:
        haproxy.stop()
        sleep(10)
        for instance in running_instances:
            instance.stop_all_ssh_tunnels()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--templates_dir",       help="Directory where are stored jinja2 templates", required=True)
    parser.add_argument("--haproxy_template",    help="HAProxy template used by jinja2", required=True)
    parser.add_argument("--keyfile",             help="ssh key used to connect to cloud instances", required=True)

    parser.add_argument("--provider",            help="Cloud provider", choices=['vultr', 'digitalocean', 'aws', 'kamatera', 'linode', 'upcloud'], required=True)
    parser.add_argument("--client_id",           help="client id required by kamatera api", required=False, default=None)
    parser.add_argument("--api_key",             help="api key used to connect to cloud API", required=True)
    parser.add_argument("--os_id",               help="os id used for booting instances", required=True)
    parser.add_argument("--plan",                help="plan used for instances", required=True)
    parser.add_argument("--region",              help="region where to launch instances", required=True)
    parser.add_argument("--sshkey_id",           help="ssh key id to install on instances", required=True)
    parser.add_argument("--tag",                 help="optional tag, used to distinguish instances in the same region from the same provider", required=False, default=None)

    parser.add_argument("--required_instances",  help="Number of instances to run simulteanously", required=True, type=int)
    parser.add_argument("--instances_ttl",       help="Time after instances will be remplaced by new ones", required=True, type=int)
    parser.add_argument("--tunnels_by_instance", help="Number of ssh tunnels established per cloud instance", required=True, type=int)

    parser.add_argument("--loop_time",           help="Time to wait between two loops iterations", default=60, type=int)
    parser.add_argument("--wait_time",           help="Time to wait before reload haproxy conf or deleting ssh tunnels", default=60, type=int)

    args = parser.parse_args()

    # Args Examples
    #templates_dir    = '/templates'
    #haproxy_template = 'haproxy.cfg.tmpl'
    #keyfile = '/ssh-key/id_rsa_vultr'
    #api_key = 'XXXXXXXXXXXx'
    #os_id    = 477
    #plan    = 'vc2-1c-1gb'
    #region  = 'lhr'
    #sshkey_id = 'e7752200-ec77-462d-92be-511106a943be'

    #required_instances = 2
    #instances_ttl     = 900

    main(
        args.loop_time,
        args.wait_time,
        args.keyfile,
        args.provider,
        args.client_id,
        args.api_key,
        args.os_id,
        args.plan,
        args.region,
        args.sshkey_id,
        args.tag,
        args.templates_dir,
        args.haproxy_template,
        args.instances_ttl,
        args.tunnels_by_instance,
        required_instances=args.required_instances
    )
