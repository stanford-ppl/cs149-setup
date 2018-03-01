#!/usr/bin/env python
#### Author: Elliott Slaughter <elliottslaughter@gmail.com>
####
#### Copyright (c) 2014, Stanford University
####
#### Permission is hereby granted, free of charge, to any person
#### obtaining a copy of this software and associated documentation
#### files (the "Software"), to deal in the Software without
#### restriction, including without limitation the rights to use, copy,
#### modify, merge, publish, distribute, sublicense, and/or sell copies
#### of the Software, and to permit persons to whom the Software is
#### furnished to do so, subject to the following conditions:
####
#### The above copyright notice and this permission notice shall be
#### included in all copies or substantial portions of the Software.
####
#### THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#### EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
#### MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#### NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
#### HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
#### WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#### OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#### DEALINGS IN THE SOFTWARE.
####

import argparse, base64, boto.ec2, collections, copy, csv, datetime, email, itertools, json, os, re, smtplib, stat, subprocess, sys, tempfile, time

###
### JSON Files
###

def load_json(filename):
    with open(filename, 'rb') as f:
        return json.load(f, object_pairs_hook=collections.OrderedDict)

def dump_json(config_values, filename):
    with open(filename, 'wb') as f:
        json.dump(config_values, f)

def init_json(config_filename, defaults_filename = None):
    config = collections.OrderedDict()
    if defaults_filename is not None:
        config = load_json(defaults_filename)
    if os.path.exists(config_filename):
        config.update(load_json(config_filename))
    return config

def is_stale(filename):
    now = datetime.datetime.now()
    age = datetime.datetime.fromtimestamp(os.path.getmtime(filename))
    return now - age > datetime.timedelta(days = 60)

def check_json_staleness(filename):
    if not os.path.exists(filename):
        return True
    if is_stale(filename):
        age = datetime.datetime.fromtimestamp(os.path.getmtime(filename))
        suffix = age.strftime('%Y-%m-%d')
        backup_filename = '%s.%s' % (filename, suffix)

        print 'This configuration appears to be stale (maybe from a previous quarter?).'
        print 'Would you like a fresh configuration?'
        print
        print 'This will move the file "%s" to "%s"' % (
            os.path.basename(filename), os.path.basename(backup_filename))
        print 'for easy recovery if something goes wrong.'
        print

        cont = False
        while True:
            cont = raw_input('Start with fresh configuration? ')
            if cont.lower() == 'yes':
                cont = True
                break
            if cont.lower() == 'no':
                cont = False
                break
            print 'Yes or no please.'
        print
        if not cont: return False

        os.rename(filename, backup_filename)
        return True
    return False

def query_json(defaults):
    print 'Please verify that the following configuration is correct.'
    config = collections.OrderedDict()
    for query, default in defaults.iteritems():
        while True:
            raw_value = raw_input('%s (%s)? ' % (query, json.dumps(default)))
            value = default
            if len(raw_value) > 0:
                try:
                    value = json.loads(
                        raw_value,
                        object_pairs_hook = collections.OrderedDict)
                except ValueError:
                    print 'Please provide a valid JSON value.'
                    continue
            break
        config[query] = value
    return config

def init_json_interactive(config_filename, defaults_filename, force_query):
    query = False
    config = load_json(defaults_filename)
    if os.path.exists(config_filename):
        previous_config = load_json(config_filename)
        config.update(previous_config)
        if previous_config != config:
            query = True
    else:
        query = True
    if query or force_query:
        config = query_json(config)
        dump_json(config, config_filename)
    return config

###
### Amazon EC2 Management
###

def connect(cx):
    ec2_account = cx.secret['AWS IAM Accounts']['EC2']
    return boto.ec2.connect_to_region(
        cx.secret['AWS Region'],
        aws_access_key_id = ec2_account['AWS Access Key ID'],
        aws_secret_access_key = ec2_account['AWS Secrect Access Key'])

def create_key(cx, key_name, key_filename):
    if not os.path.exists(key_filename):
        if cx.connection.get_key_pair(key_name) is not None:
            raise Exception('Key "%s" already exists' % key_name)
        print 'Creating key pair "%s"...' % key_name
        key = cx.connection.create_key_pair(key_name)
        with open(key_filename, 'wb') as f:
            f.write(key.material)
        os.chmod(key_filename, stat.S_IRUSR)

def get_security_group(cx, name):
    groups = cx.connection.get_all_security_groups()
    for group in groups:
        if str(group.name) == str(name):
            return group
    return None

def create_security_group(cx, name):
    security_group = get_security_group(cx, name)

    if security_group is None:
        print 'Creating security group "%s"...' % name

        security_group = cx.connection.create_security_group(name, name)
        # Configure the firewall to allow SSH from anywhere, and any
        # protocol from within the same security group.
        #
        # Technically we only need the following ports open:
        #    22 TCP         (SSH)
        #    88 UDP         (Kerberos)
        #   389 TCP         (LDAP)
        #   750 UDP         (Kerberos)
        #  2049 TCP         (NFS)
        # 15001 TCP and UDP (Torque)
        # 15002 TCP and UDP (Torque)
        # 15003 TCP and UDP (Torque)
        # 15004 TCP and UDP (Torque)
        #
        # However, Torque likes to misbehave and open other ports in
        # an unpredictable way, which makes maintaining a reasonable
        # firewall policy difficult.
        assert security_group.authorize(
            ip_protocol = 'tcp',
            from_port = 22,
            to_port = 22,
            cidr_ip = '0.0.0.0/0')
        assert security_group.authorize(
            src_group = security_group)
    return security_group

def wait_for_object_state(cx, obj, obj_type, expected_state):
    sys.stdout.write('Waiting for %s "%s" to enter state "%s"' % (
            obj_type, obj.id, expected_state))
    sys.stdout.flush()
    time.sleep(1.0)
    while True:
        try:
            obj.update()
        except boto.exception.EC2ResponseError:
            sys.stdout.write('!')
            sys.stdout.flush()
            continue
        if obj.state == expected_state:
            break
        sys.stdout.write('.')
        sys.stdout.flush()
        time.sleep(5.0)
    print

def wait_for_image_state(cx, image_id, expected_state = 'available'):
    image = cx.connection.get_image(image_id)
    wait_for_object_state(cx, image, 'image', expected_state)

def wait_for_instance_state(cx, instance, expected_state = 'running'):
    wait_for_object_state(cx, instance, 'instance', expected_state)

_re_boot_finished = re.compile(r'Cloud-init')
_re_host_keys = re.compile(
    r'-----BEGIN SSH HOST KEY KEYS-----(.*)-----END SSH HOST KEY KEYS-----',
    re.DOTALL)
def get_instance_host_keys(cx, instance):
    sys.stdout.write('Waiting for instance "%s" host key' % instance.id)
    sys.stdout.flush()
    while True:
        time.sleep(5.0)
        try:
            output = instance.get_console_output().output
            if output is None or len(output) == 0:
                sys.stdout.write('.')
                sys.stdout.flush()
                continue
            if re.search(_re_boot_finished, output) is None:
                sys.stdout.write('?')
                sys.stdout.flush()
                continue
            break
        except boto.exception.EC2ResponseError:
            sys.stdout.write('!')
            sys.stdout.flush()
            continue
    print
    match = re.search(_re_host_keys, output)
    if match is None:
        raise Exception('Error: No host key in console output.')
    return [line.strip() for line in match.group(1).strip().split('\n')]

def save_instance_host_keys(cx, instance):
    wait_for_instance_state(cx, instance)
    keys = get_instance_host_keys(cx, instance)

    known_hosts_filename = os.path.join(
        os.path.expanduser('~'), '.ssh', 'known_hosts')
    with open(known_hosts_filename, 'ab') as f:
        host = '%s,%s' % (instance.public_dns_name, instance.ip_address)
        host_key_pairs = '\n'.join('%s %s' % (host, key) for key in keys)
        f.write(host_key_pairs)

    return keys

def create_instance(cx, count, instance_type, image_id, volume_size,
                    disable_api_termation, name):
    if count == 0:
        return []

    wait_for_image_state(cx, image_id)
    print 'Creating %s "%s" instances for "%s"...' % (count, instance_type, image_id)

    # Request a volume of the appropriate size.
    block_device_map = boto.ec2.blockdevicemapping.BlockDeviceMapping()
    block_device_map['/dev/sda1'] = boto.ec2.blockdevicemapping.BlockDeviceType(
        delete_on_termination = True,
        size = volume_size)

    # Request an instance.
    reservation = cx.connection.run_instances(
        image_id = image_id,
        min_count = count,
        max_count = count,
        key_name = cx.key_name,
        instance_type = instance_type,
        security_groups = [cx.security_group],
        block_device_map = block_device_map,
        disable_api_termination = disable_api_termation)
    assert len(reservation.instances) == count

    cx.connection.create_tags(
        [instance.id for instance in reservation.instances],
        {'Name': name})

    print 'Created instances %s' % ' '.join('"%s"' % instance.id for instance in reservation.instances)
    return reservation.instances

def get_instance(cx, instance_id):
    reservations = cx.connection.get_all_instances([instance_id])
    assert len(reservations) == 1 and len(reservations[0].instances) == 1
    return reservations[0].instances[0]

def stop_instance(cx, instance):
    print 'Waiting for instance "%s" to stop...' % instance.id
    instance.stop()
    wait_for_instance_state(cx, instance, 'stopped')

def terminate_instance(cx, instance):
    print 'Terminating instance "%s"...' % instance.id
    instance.terminate()

def create_image(instance, image_name):
    print 'Creating image from instance "%s"...' % instance.id
    return instance.create_image(image_name)

###
### Instance Management
###

def remote_command_retry_menu():
    options = set(['retry', 'skip', 'quit'])
    print 'What would you like to do?'
    print '  Retry: Retry the command.'
    print '  Skip:  Skip this command and continue as if it had succeeded.'
    print '  Quit:  Give up and abort (may create inconsistent state).'
    while True:
        option = raw_input('Choice? ')
        if option.lower().strip() in options:
            return option
        print 'What was that?'

def remote_command_retry_handler(cx, thunk, allow_retry):
    assert cx.node_name is not None

    while True:
        try:
            return thunk()
        except subprocess.CalledProcessError as exception:
            if not allow_retry:
                raise exception
            print 'Error: Remote command failed.'
            print
            print exception.cmd
            print
            print exception
            option = remote_command_retry_menu()
            if option.lower().strip() == 'retry':
                continue
            elif option.lower().strip() == 'skip':
                break
            elif option.lower().strip() == 'quit':
                sys.exit(1)

def remote_command(cx, command, allow_retry = True):
    def thunk():
        subprocess.check_call([
            'ssh',
            '-i', cx.key_filename,
            '%s@%s' % (cx.username, cx.hostname),
            command])
    remote_command_retry_handler(cx, thunk, allow_retry)

def remote_commands(cx, commands):
    remote_command(cx, ' && '.join(commands))

def remote_command_output(cx, command, allow_retry = True):
    def thunk():
        return subprocess.check_output([
            'ssh',
            '-i', cx.key_filename,
            '%s@%s' % (cx.username, cx.hostname),
            command])
    return remote_command_retry_handler(cx, thunk, allow_retry)

def remote_command_retcode(cx, command, allow_retry = True):
    def thunk():
        return subprocess.call([
            'ssh',
            '-i', cx.key_filename,
            '%s@%s' % (cx.username, cx.hostname),
            command])
    return remote_command_retry_handler(cx, thunk, allow_retry)

def remote_copy(cx, local_filename, remote_filename, allow_retry = True):
    def thunk():
        subprocess.check_call([
            'scp', '-q',
            '-i', cx.key_filename,
            local_filename,
            '%s@%s:%s' % (cx.username, cx.hostname, remote_filename)])
    return remote_command_retry_handler(cx, thunk, allow_retry)

def remote_copy_back(cx, remote_filename, local_filename, allow_retry = True):
    def thunk():
        subprocess.check_call([
            'scp', '-q',
            '-i', cx.key_filename,
            '%s@%s:%s' % (cx.username, cx.hostname, remote_filename),
            local_filename])
    return remote_command_retry_handler(cx, thunk, allow_retry)

def remote_copy_with_substitutions(cx, local_filename, remote_filename,
                                   substitutions, allow_retry = True):
    def thunk():
        with tempfile.NamedTemporaryFile() as tf:
            with open(local_filename, 'rb') as lf:
                tf.write(lf.read().format(**substitutions))
            tf.flush()
            remote_copy(cx, tf.name, remote_filename)
    return remote_command_retry_handler(cx, thunk, allow_retry)

def wait_for_remote_shell(cx):
    while True:
        try:
            remote_command(cx, 'true', allow_retry = False)
            break
        except subprocess.CalledProcessError:
            print 'Waiting for remote shell...'
            time.sleep(5.0)
            continue

def install_packages(cx, packages, upgrade = True):
    commands = []
    commands.append('sudo apt-get update')
    if upgrade:
        commands.append(
            'sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y')
    commands.append(
        'sudo DEBIAN_FRONTEND=noninteractive apt-get install -y %s' % (
            ' '.join(packages)))
    remote_commands(cx, commands)

def protect_directory(cx, directory):
    remote_command(cx, 'sudo chmod og-rwx %s' % directory)

def torque_compute_node_state(cx, compute_node_name):
    status = remote_command_output(
        cx,
        'pbsnodes %s' % compute_node_name)
    return [line.strip()
            for line in status.split('\n')[1:]
            if line.strip().startswith('state = ')
            ][0].replace('state = ', '').split(',')

def disable_torque_compute_node(cx, compute_node_name):
    remote_command(
        cx,
        'sudo pbsnodes -o %s' % compute_node_name)
    sys.stdout.write('Waiting for Torque node finish remaining jobs')
    sys.stdout.flush()
    while True:
        state = torque_compute_node_state(cx, compute_node_name)
        if 'offline' not in state or len(state) > 1:
            sys.stdout.write('.')
            sys.stdout.flush()
            time.sleep(5.0)
            continue
        break
    print

def delete_torque_compute_node(cx, compute_node_name):
    remote_command(
        cx,
        'sudo qmgr -c "delete node %s"' % compute_node_name)

def configure_server_keytab(cx, principals):
    remote_commands(cx, [
            'sudo kadmin.local -q "addprinc -randkey %s"' % principal
            for principal in principals] + [
            'sudo kadmin.local -q "ktadd %s"' % principal
            for principal in principals])

def delete_kerberos_principles(cx, principals):
    remote_commands(cx, [
            'sudo kadmin.local -q "delprinc -force %s"' % principal
            for principal in principals])

def is_username_available(cx, username):
    if username in cx.state['users']:
        return False
    return 0 != remote_command_retcode(cx, 'id %s &> /dev/null' % username)

def create_user(cx, username, password, fullname, given_name, surname, uid):
    ldap_feature = find_feature(cx, 'ldap')

    addgroup_ldif = os.path.join(cx.root_dir, 'ldap', 'addgroup.ldif')
    adduser_ldif = os.path.join(cx.root_dir, 'ldap', 'adduser.ldif')

    substitutions = {
        'username': username,
        'groupname': username,
        'fullname': fullname,
        'surname': surname,
        'given_name': given_name,
        'uid': uid,
        'gid': uid,
        'shell': '/bin/bash',
        'homedir': '/users/%s' % username,
        'ldap_base': ldap_feature['ldap_base'],
    }

    remote_commands(cx, [
            r'sudo kadmin.local -q "addprinc -pw \"%s\" %s"' % (
                password, username)])
    remote_copy_with_substitutions(
        cx, addgroup_ldif, 'addgroup.ldif', substitutions)
    remote_copy_with_substitutions(
        cx, adduser_ldif, 'adduser.ldif', substitutions)
    remote_commands(cx, [
            'unset HISTFILE',
            'ldapadd -x -D cn=admin,%s -w "%s" -f addgroup.ldif' % (
                ldap_feature['ldap_base'], ldap_feature['ldap_password']),
            'ldapadd -x -D cn=admin,%s -w "%s" -f adduser.ldif' % (
                ldap_feature['ldap_base'], ldap_feature['ldap_password']),
            'shred --remove addgroup.ldif adduser.ldif',
            ])

def start_services(cx, services):
    remote_commands(
        cx,
        ['sudo service %s start' % service for service in services])

def restart_services(cx, services):
    remote_commands(
        cx,
        ['sudo service %s restart' % service for service in services])

def reload_services(cx, services):
    remote_commands(
        cx,
        ['sudo service %s reload' % service for service in services])

###
### Context
###

class Context:
    def __init__(self, root_dir):
        self.root_dir = root_dir
        stale = check_json_staleness(
            os.path.join(self.root_dir, 'config', 'state.json'))
        self.secret = init_json_interactive(
            os.path.join(self.root_dir, 'config', 'secret.json'),
            os.path.join(self.root_dir, 'config', 'default.secret.json'),
            stale)
        self.config = init_json(
            os.path.join(self.root_dir, 'config', 'config.json'))
        self.state = init_json(
            os.path.join(self.root_dir, 'config', 'state.json'),
            os.path.join(self.root_dir, 'config', 'default.state.json'))
        self.connection = None
        self.key_filename = None
        self.key_name = None
        self.security_group = None
        self.cluster_name = None
        self.cluster = None
        self.node_name = None
        self.node = None
        self.username = None
        self.hostname = None

        self.validate()
    def new_cluster_scope(self, cluster_name):
        cx = copy.copy(self)
        cx.cluster_name = cluster_name
        cx.cluster = cx.state['clusters'][cx.cluster_name]
        cx.node_name = None
        cx.node = None
        cx.username = None
        cx.hostname = None
        return cx
    def new_node_scope(self, node_name):
        cx = copy.copy(self)
        cx.cluster_name = cx.state['nodes'][node_name]['cluster_name']
        cx.cluster = cx.state['clusters'][cx.cluster_name]
        cx.node_name = node_name
        cx.node = cx.state['nodes'][node_name]
        cx.username = 'ubuntu'
        cx.hostname = cx.state['nodes'][node_name]['public_dns_name']
        return cx
    def validate(self):
        names = {}

        for module in self.config['Modules'].iterkeys():
            if module in names:
                raise Exception('Module "%s" already defined as a %s' % (
                    module, names[module]))
            names[module] = 'module'

        for node in self.config['Nodes'].iterkeys():
            if node in names:
                raise Exception('Node "%s" already defined as a %s' % (
                    node, names[node]))
            names[node] = 'node'

        for cluster in self.config['Clusters'].iterkeys():
            if cluster in names:
                raise Exception('Cluster "%s" already defined as a %s' % (
                    cluster, names[cluster]))
            names[cluster] = 'cluster'

        for recipe in self.config['Recipes'].iterkeys():
            if recipe in names:
                raise Exception('Recipe "%s" already defined as a %s' % (
                    recipe, names[recipe]))
            names[recipe] = 'recipe'

    def persist_state(self):
        dump_json(
            self.state,
            os.path.join(self.root_dir, 'config', 'state.json'))

###
### Features
###

def add_feature(cx, feature, additional = None):
    if additional is not None:
        additional[feature] = collections.OrderedDict([
            ('node', cx.node_name),
        ])
        return additional[feature]

    cluster = cx.state['clusters'][cx.cluster_name]
    cluster['features'][feature] = collections.OrderedDict([
        ('node', cx.node_name),
    ])
    return cluster['features'][feature]

def find_feature(cx, feature, recursive = True, additional = None):
    if additional is not None and feature in additional:
        return additional[feature]

    cluster = cx.state['clusters'][cx.cluster_name]
    if feature in cluster['features']:
        return cluster['features'][feature]

    if recursive and cluster['parent'] is not None:
        cx = cx.new_cluster_scope(cluster['parent'])
        return find_feature(cx, feature, recursive)

    return None

###
### Configurations
###

def configure_tmp(cx):
    tmp_config = os.path.join(cx.root_dir, 'etc', 'systemd', 'system', 'tmp.service')

    remote_copy(cx, tmp_config, 'tmp.service')
    remote_commands(cx, [
        'sudo chown root:root tmp.service',
        'sudo chmod 644 tmp.service',
        'sudo mv tmp.service /etc/systemd/system/tmp.service',
        'sudo systemctl start tmp'
    ])
    #remote_commands(cx, [
    #    'sudo systemctl status tmp.service',
    #    'sudo journalctl -xe'])

def configure_pip_install(cx, packages):
    remote_commands(cx, [
        'sudo pip install %s' % (' '.join(packages))
    ])

def configure_cuda_base(cx):
    # This installs ONLY the toolkit part of CUDA, which is enough to
    # run the CUDA compiler but not enough to run CUDA itself.
    remote_commands(cx, [
        'wget --progress=dot:mega https://developer.nvidia.com/compute/cuda/8.0/prod/local_installers/cuda_8.0.44_linux-run',
        'echo "016fe98f55a49e36479602da7b8d12a130b6c83e  cuda_8.0.44_linux-run" | shasum --check',
        'TERM=xterm sudo sh cuda_8.0.44_linux-run -silent -toolkit',
        # The installer doesn't provide a meaningful return value,
        # so check for success manually.
        'test -d /usr/local/cuda-8.0',
        r'sudo bash -c "source /etc/environment && echo \"PATH=\\\"\$PATH:/usr/local/cuda-8.0/bin\\\"\" > /etc/environment"',
        'rm cuda_8.0.44_linux-run',
    ])

def configure_cuda_full(cx):
    # This installs all of CUDA, which makes it quite a bit more involved.
    gpu_config = os.path.join(cx.root_dir, 'etc', 'systemd','system', 'nvidia_gpu.conf')
    remote_copy(cx, gpu_config, 'nvidia_gpu.conf')
    #throws an error but just SKIP as it actually works fine
    remote_command(cx,
      r'wget --progress=dot:mega https://developer.nvidia.com/compute/cuda/8.0/prod/local_installers/cuda_8.0.44_linux-run'
    )
    remote_command(cx,
      r'echo "016fe98f55a49e36479602da7b8d12a130b6c83e  cuda_8.0.44_linux-run" | shasum --check'
    )
    remote_command(cx,
      r'sudo apt-get install openjdk-8-jdk git python-dev python3-dev python-numpy python3-numpy build-essential python-pip python3-pip python3-venv swig python3-wheel libcurl3-dev'
    )
    remote_command(cx,
      r'sudo apt-get install -y gcc g++ gfortran git linux-image-generic linux-headers-generic linux-source linux-image-extra-virtual libopenblas-dev'
    )

    remote_command(cx, 
        r'sudo sh -c "echo \"blacklist nouveau\" >> /etc/modprobe.d/blacklist.conf"')

    remote_command(cx, 
        r'sudo sh -c "echo \"options nouveau modeset=0\" >> /etc/modprobe.d/blacklist.conf"')

    remote_command(cx, 
        r'sudo update-initramfs -u')

    #subprocess.call([
    #        'ssh',
    #        '-i', cx.key_filename,
    #        '%s@%s' % (cx.username, cx.hostname),
    #        r'sudo reboot'])
    
    #command fails sometimes, make sure the instance on the web reboots then just skip
    remote_command(cx,r'sudo reboot')
    time.sleep(5.0)
    wait_for_remote_shell(cx)

    comm="""
    remote_commands(cx, [
        'wget --progress=dot:mega https://developer.nvidia.com/compute/cuda/8.0/prod/local_installers/cuda_8.0.44_linux-run',
        'echo "016fe98f55a49e36479602da7b8d12a130b6c83e  cuda_8.0.44_linux-run" | shasum --check',
        'TERM=xterm sudo sh cuda_8.0.44_linux-run -silent -driver -toolkit',
        # The installer doesn't provide a meaningful return value,
        # so check for success manually.
        'test -d /usr/local/cuda-8.0',
        r'sudo bash -c "source /etc/environment && echo \"PATH=\\\"\$PATH:/usr/local/cuda-8.0/bin\\\"\" > /etc/environment"',
        r'sudo bash -c "echo \"# CUDA Libraries\" >> /etc/ld.so.conf.d/cuda.conf"',
        r'sudo bash -c "echo \"/usr/local/cuda-8.0/lib64\" >> /etc/ld.so.conf.d/cuda.conf"',
        r'sudo bash -c "echo \"/lib\" >> /etc/ld.so.conf.d/cuda.conf"',
        'sudo ldconfig',
        'sudo chown root:root nvidia_gpu.conf',
        'sudo chmod 644 nvidia_gpu.conf',
        'sudo mv nvidia_gpu.conf /etc/systemd/system/nvidia_gpu.conf',
        'rm cuda_8.0.44_linux-run',
    ])
    """

def configure_timezone(cx):
    remote_commands(cx, [
            r'sudo bash -c "echo \"America/Los_Angeles\" > /etc/timezone"',
            'sudo dpkg-reconfigure --frontend noninteractive tzdata'])

def configure_ssh_server(cx):
    ssh_config = os.path.join(cx.root_dir, 'ssh', 'ssh_config')
    sshd_config = os.path.join(cx.root_dir, 'ssh', 'sshd_config')

    remote_copy(cx, sshd_config, 'sshd_config')
    remote_copy(cx, ssh_config, 'ssh_config')
    remote_commands(cx, [
        'sudo chown root:root sshd_config',
        'sudo chmod 644 sshd_config',
        'sudo mv sshd_config /etc/ssh/sshd_config',
        'sudo chown root:root ssh_config',
        'sudo chmod 644 ssh_config',
        'sudo mv ssh_config /etc/ssh/ssh_config',
    ])

def configure_krb5_server(cx):
    hostname = cx.node['private_dns_name']

    krb5_feature = add_feature(cx, 'krb5')
    krb5_feature['krb5_kdc_hostname'] = hostname
    krb5_feature['krb5_admin_hostname'] = hostname
    krb5_feature['krb5_domain'] = '.'.join(hostname.split('.')[1:])
    krb5_feature['krb5_realm'] = '.'.join(hostname.split('.')[1:]).upper()
    krb5_feature['krb5_kdc_password'] = base64.b64encode(os.urandom(30))
    krb5_feature['krb5_root_username'] = 'ubuntu'
    krb5_feature['krb5_root_password'] = base64.b64encode(os.urandom(30))

    krb5_conf_filename = os.path.join(cx.root_dir, 'krb5', 'krb5.conf')
    kadm5_acl_filename = os.path.join(cx.root_dir, 'krb5', 'kadm5.acl')

    host_principal = 'host/%s@%s' % (hostname, krb5_feature['krb5_realm'])

    substitutions = krb5_feature

    remote_copy_with_substitutions(
        cx, krb5_conf_filename, 'krb5.conf', substitutions)
    remote_copy(cx, kadm5_acl_filename, 'kadm5.acl')
    remote_commands(cx, [
        # Install configuration files.
        'sudo chown root:root krb5.conf',
        'sudo chmod 644 krb5.conf',
        'sudo mv krb5.conf /etc/krb5.conf',
        'sudo chown root:root kadm5.acl',
        'sudo chmod 644 kadm5.acl',
        'sudo mv kadm5.acl /etc/krb5kdc/kadm5.acl',

        # WARNING: The following command undermines the randomness of
        # the system random number generator and may result in broken
        # cryptography in Kerberos and other security-critical
        # systems!!!!
        #
        # FIXME: This command connects a pseudo-random generator to
        # /dev/urandom which is normally supposed to be "truly"
        # random. Without this command, Amazon EC2 has trouble
        # gathering enough entropy to satisfy Kerberos, and the
        # command to create a KDC will take a very logn time.
        #'sudo rngd -r /dev/urandom -o /dev/random -t 1',

        # Create Kerberos database.
        'unset HISTFILE', # protect passwords
        'sudo kdb5_util create -s -P "%s"' % krb5_feature['krb5_kdc_password'],

        # Start KDC and admin servers.
        'sudo service krb5-kdc start',
        'sudo service krb5-admin-server start',

        # Create initial principals for users and services.
        r'sudo kadmin.local -q "addprinc -pw \"%s\" %s"' % (
            krb5_feature['krb5_root_password'],
            krb5_feature['krb5_root_username']),
        'sudo kadmin.local -q "addprinc -randkey %s"' % host_principal,
        'sudo kadmin.local -q "ktadd %s"' % host_principal,
    ])

def configure_krb5_client(cx):
    krb5_feature = find_feature(cx, 'krb5')
    server_cx = cx.new_node_scope(krb5_feature['node'])

    krb5_conf_filename = os.path.join(cx.root_dir, 'krb5', 'krb5.conf')

    hostname = cx.node['private_dns_name']
    host_principal = 'host/%s@%s' % (hostname, krb5_feature['krb5_realm'])

    substitutions = krb5_feature

    # Create a keytab for the client.
    remote_commands(server_cx, [
        'sudo kadmin.local -q "addprinc -randkey %s"' % host_principal,
        'sudo kadmin.local -q "ktadd -keytab /root/host.keytab %s"' % (
            host_principal),
        'sudo mv /root/host.keytab host.keytab',
        'sudo chown ubuntu:ubuntu host.keytab'])
    with tempfile.NamedTemporaryFile() as tf:
        remote_copy_back(server_cx, 'host.keytab', tf.name)
        remote_copy(cx, tf.name, 'host.keytab')
    remote_commands(cx, [
        'sudo chown root:root host.keytab',
        'sudo chmod 600 host.keytab',
        'sudo mv host.keytab /etc/krb5.keytab'])
    remote_commands(server_cx, [
        'shred --remove host.keytab'])

    # Configure the client.
    remote_copy_with_substitutions(
        cx, krb5_conf_filename, 'krb5.conf', substitutions)
    remote_commands(cx, [
        'sudo chown root:root krb5.conf',
        'sudo chmod 644 krb5.conf',
        'sudo mv krb5.conf /etc/krb5.conf',
    ])

def configure_terminate_krb5_client(cx):
    krb5_feature = find_feature(cx, 'krb5')
    server_cx = cx.new_node_scope(krb5_feature['node'])

    instance_name = cx.node['private_dns_name']

    # Delete Kerberos principle
    delete_kerberos_principles(
        server_cx,
        ['host/%s' % instance_name])

def configure_ldap_server(cx):
    hostname = cx.node['private_dns_name']

    krb5_feature = find_feature(cx, 'krb5')
    ldap_feature = add_feature(cx, 'ldap')
    ldap_feature['ldap_top'] = 'cn=%s' % hostname
    ldap_feature['ldap_base'] = 'dc=%s' % ',dc='.join(hostname.split('.')[1:])
    ldap_feature['ldap_uri'] = 'ldap://%s' % hostname
    ldap_feature['ldap_password'] = base64.b64encode(os.urandom(30))

    root_password_filename = os.path.join(
        cx.root_dir, 'ldap', 'root_password.ldif')
    categories_filename = os.path.join(
        cx.root_dir, 'ldap', 'categories.ldif')
    ldap_krb5_filename = os.path.join(
        cx.root_dir, 'ldap', 'ldap_krb5.ldif')

    ldap_principal = 'host/%s@%s' % (hostname, krb5_feature['krb5_realm'])

    substitutions = {}
    substitutions.update(krb5_feature)
    substitutions.update(ldap_feature)

    remote_copy(
        cx, root_password_filename, 'root_password.ldif')
    remote_copy_with_substitutions(
        cx, ldap_krb5_filename, 'ldap_krb5.ldif', substitutions)
    remote_copy_with_substitutions(
        cx, categories_filename, 'categories.ldif', substitutions)
    remote_commands(cx, [
        # Create LDAP principal.
        'sudo kadmin.local -q "addprinc -randkey %s"' % ldap_principal,
        'sudo kadmin.local -q "ktadd %s"' % ldap_principal,

        # Configure LDAP database.
        'unset HISTFILE',
        'echo "olcRootPW: $(slappasswd -s %s)" >> root_password.ldif' % (
            ldap_feature['ldap_password']),
        'sudo ldapmodify -Y EXTERNAL -H ldapi:/// -f root_password.ldif',
        'sudo ldapadd -Y EXTERNAL -H ldapi:/// -f ldap_krb5.ldif',
        'ldapadd -x -D cn=admin,%s -w "%s" -f categories.ldif' % (
            ldap_feature['ldap_base'], ldap_feature['ldap_password']),

        # Configure LDAP transport to use Kerberos.
        r'sudo sh -c "echo \"SASL_MECH GSSAPI\" >> /etc/ldap/ldap.conf"',
        r'sudo sh -c "echo \"SASL_REALM %s\" >> /etc/ldap/ldap.conf"' % (
            krb5_feature['krb5_realm']),
        'shred --remove root_password.ldif ldap_krb5.ldif categories.ldif',
    ])

def configure_ldap_client(cx):
    ldap_feature = find_feature(cx, 'ldap')

    krb_auth_config = os.path.join(
        cx.root_dir, 'ldap', 'krb-auth-config')
    pam_common_session = os.path.join(
        cx.root_dir, 'etc', 'pam.d', 'common-session')

    remote_copy(cx, krb_auth_config, 'krb-auth-config')
    remote_copy(cx, pam_common_session, 'common-session')
    remote_commands(cx, [
        # Configure LDAP client.
        'sudo sh -c "echo > /etc/ldap.conf"',
        'sudo sh -c "echo base %s >> /etc/ldap.conf"' % (
            ldap_feature['ldap_base']),
        'sudo sh -c "echo uri %s >> /etc/ldap.conf"' % (
            ldap_feature['ldap_uri']),
        'sudo sh -c "echo ldap_version 3 >> /etc/ldap.conf"',

        # Configure Kerberos authentication.
        'sudo chown root:root krb-auth-config',
        'sudo chmod 644 krb-auth-config',
        'sudo mv krb-auth-config /etc/auth-client-config/profile.d/krb-auth-config',
        'sudo auth-client-config -a -p krb5ldap',

        # Configure PAM.
        'sudo chown root:root common-session',
        'sudo chmod 644 common-session',
        'sudo mv common-session /etc/pam.d/common-session',
    ])

def configure_nfs_server(cx):
    nfs_feature = add_feature(cx, 'nfs')

    nfs_kernel_server_filename = os.path.join(
        cx.root_dir, 'nfs', 'nfs-kernel-server')

    remote_copy(cx, nfs_kernel_server_filename, 'nfs-kernel-server')
    remote_commands(cx, [
        'sudo mkdir /users',
        'sudo mkdir /export',
        'sudo mkdir /export/users',
        'sudo mount --bind /users /export/users',
        r'sudo sh -c "echo \"/users /export/users none bind 0 0\" >> /etc/fstab"',
        'sudo chown root:root nfs-kernel-server',
        'sudo chmod 644 nfs-kernel-server',
        'sudo mv nfs-kernel-server /etc/default/nfs-kernel-server',
        r'sudo sh -c "echo \"/export 10.0.0.0/8(rw,sync,fsid=0,crossmnt,no_subtree_check)\" >> /etc/exports"',
        r'sudo sh -c "echo \"/export/users 10.0.0.0/8(rw,sync,no_subtree_check)\" >> /etc/exports"',
        'sudo service nfs-kernel-server restart',
    ])

def configure_nfs_client(cx):
    nfs_feature = find_feature(cx, 'nfs')

    server_name = cx.state['nodes'][nfs_feature['node']]['private_dns_name']

    nfs_common_filename = os.path.join(cx.root_dir, 'nfs', 'nfs-common')

    remote_copy(cx, nfs_common_filename, 'nfs-common')
    remote_commands(cx, [
        'sudo chown root:root nfs-common',
        'sudo chmod 644 nfs-common',
        'sudo mv nfs-common /etc/default/nfs-common',
        'sudo mkdir /users',
        'sudo mount %s:/users /users' % server_name
    ])

def configure_torque_server(cx, torque_config):
    torque_feature = add_feature(cx, 'torque')

    commands = [
        'sudo sh -c "hostname --fqdn > /var/spool/torque/server_name"',
        r'sudo bash -c "source /etc/environment && echo \"PATH=\$PATH\" > /var/spool/torque/pbs_environment"',
        r'sudo sh -c "echo \"RERUNNABLEBYDEFAULT false\" >> /var/spool/torque/torque.cfg"',
        'sudo service torque-server restart',
        'sudo qmgr -c "set server acl_hosts -= torqueserver"',
    ]
    settings = []
    for object_type, object_configs in torque_config.iteritems():
        for object_config in object_configs:
            object_name = object_config.get('name')
            if object_name is not None:
                settings.append('create %s %s' % (
                        object_type, object_name))
            if 'attributes' in object_config:
                for name, value in object_config['attributes'].iteritems():
                    if object_name is not None:
                        settings.append('set %s %s %s = %s' % (
                            object_type, object_name,
                            name, value))
                    else:
                        settings.append('set %s %s = %s' % (
                            object_type,
                            name, value))
    commands.extend(
        'sudo qmgr -c "%s"' % setting for setting in settings)
    remote_commands(cx, commands)

def configure_torque_client(cx):
    torque_feature = find_feature(cx, 'torque')

    server_cx = cx.new_node_scope(torque_feature['node'])
    client_name = cx.node['private_dns_name']
    server_name = server_cx.node['private_dns_name']

    remote_command(
        server_cx,
        'sudo qmgr -c "create node %s"' % client_name)
    remote_commands(cx, [
        r'sudo sh -c "echo %s > /var/spool/torque/server_name"' % server_name,
        r'sudo bash -c "source /etc/environment && echo \"PATH=\$PATH\" > /var/spool/torque/pbs_environment"',
        r'sudo sh -c "echo \"\\\$pbsserver %s\" > /var/spool/torque/mom_priv/config"' % (
            server_name),
        r'sudo sh -c "echo \"\\\$usecp *:/users /users\" >> /var/spool/torque/mom_priv/config"',
        # Restart torque to reload the passwd file. Note: This fails
        # intermittently, thus the loop.
        'sudo service torque-mom restart',
        'sleep 1',
        'while ! ps --pid $(cat /var/spool/torque/mom_priv/mom.lock); do sudo service torque-mom restart; sleep 1; done',
    ])

def configure_terminate_torque_client(cx):
    torque_feature = find_feature(cx, 'torque')
    server_cx = cx.new_node_scope(torque_feature['node'])

    # Mark node offline in Torque
    disable_torque_compute_node(server_cx, cx.node['private_dns_name'])

    # Delete node in Torque
    delete_torque_compute_node(server_cx, cx.node['private_dns_name'])

def configure_spark_base(cx):
    """
    Installs Spark on each node.
    """
    spark_home = '/usr/local/spark-2.1.0-bin-hadoop2.4'
    spark_log_dir = '/var/log/spark'
    remote_commands(cx, [
        'sudo adduser --firstuid 1001 --disabled-password --gecos "" spark',
        'wget --progress=dot:mega http://www-eu.apache.org/dist/spark/spark-2.1.0/spark-2.1.0-bin-hadoop2.4.tgz',
        'sudo tar xfz spark-2.1.0-bin-hadoop2.4.tgz -C /usr/local',
        'sudo mkdir %s' % spark_log_dir,
        'rm spark-2.1.0-bin-hadoop2.4.tgz'

        ])
    print "configure_spark_base"

def configure_spark_server(cx):
    """
    Spins up a Spark Master node, and write the URL to /usr/loca/etc/master
    so jobs can pull the name. Also installs sbt.
    """
    print 'called configure_spark_server'
    spark_feature = add_feature(cx, 'spark')

    server_name = cx.state['nodes'][spark_feature['node']]['private_dns_name']
    spark_feature['master'] = server_name
    spark_feature['master_port'] = 7077
    spark_feature['user_dir'] = '/user'

    master_url = "spark://{}:{}".format(\
            spark_feature['master'], spark_feature['master_port'])

    spark_home = '/usr/local/spark-2.1.0-bin-hadoop2.4'
    start_master = spark_home + "/sbin/start-master.sh -h {} -p {}".format(
            spark_feature['master'],
            spark_feature['master_port'])
    remote_commands(cx, [
        r'sudo apt-get install scala',
        r'echo "deb https://dl.bintray.com/sbt/debian /" | sudo tee -a /etc/apt/sources.list.d/sbt.list',
        r'sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 2EE0EA64E40A89B84B2DF73499E82A75642AC823',
        r'sudo apt-get update',
        r'sudo apt-get install sbt',
        r'sudo bash -c "echo \"{}\" > /usr/local/etc/master"'.format(master_url),
        # NOTE: This depends on the instance type chosen.
        r'sudo bash -c "echo spark.executor.memory 25g > {}/conf/spark-defaults.conf"'.format(spark_home),
        r'sudo {}'.format(start_master)
        ])

def configure_spark_client(cx):
    print "configure_spark_client"
    spark_feature = find_feature(cx, 'spark')
    server_cx = cx.new_node_scope(spark_feature['node'])
    master_url = "spark://{}:{}".format(\
            spark_feature['master'], spark_feature['master_port'])

    spark_home = '/usr/local/spark-2.1.0-bin-hadoop2.4'
    start_worker = spark_home + "/sbin/start-slave.sh {}".format(master_url)
    remote_commands(cx, [
        r'sudo {}'.format(start_worker)
        ])

def configure_spark_dataset(cx, _):
    pass

def configure_spark_torque_client(cx):
    spark_feature = find_feature(cx, 'spark')
    server_cx = cx.new_node_scope(spark_feature['node'])

    remote_copy(
        server_cx,
        os.path.join(cx.root_dir, 'scripts', 'kill_all_spark_jobs.sh'),
        'prologue')
    remote_commands(server_cx, [
        'sudo chown root:root prologue',
        'sudo chmod 500 prologue',
        'sudo mv prologue /var/spool/torque/mom_priv/prologue',
    ])

    configure_torque_client(server_cx)

def configure_terminate_spark_torque_client(cx):
    spark_feature = find_feature(cx, 'spark')
    server_cx = cx.new_node_scope(spark_feature['node'])

    configure_terminate_torque_client(server_cx)

def configure_skeleton(cx):
    skel_profile = os.path.join(cx.root_dir, 'etc', 'skel', '.profile')
    skel_bashrc = os.path.join(cx.root_dir, 'etc', 'skel', '.bashrc')

    remote_copy(cx, skel_profile, 'skel-profile')
    remote_copy(cx, skel_bashrc, 'skel-bashrc')
    remote_commands(cx, [
        'sudo chown root:root skel-profile',
        'sudo chmod 644 skel-profile',
        'sudo mv skel-profile /etc/skel/.profile',
        'sudo chown root:root skel-bashrc',
        'sudo chmod 644 skel-bashrc',
        'sudo mv skel-bashrc /etc/skel/.bashrc',
    ])

def configure_monitoring(cx, interval, remote_scripts):
    local_scripts = [
        os.path.join(cx.root_dir, 'scripts', script)
        for script in remote_scripts]

    home = '/home/ubuntu'
    for local_script, remote_script in zip(local_scripts, remote_scripts):
        remote_copy(cx, local_script, remote_script)
    remote_commands(cx, [
            'rm -f crontab.txt'] + [
            'chmod 755 %s' % remote_script
            for remote_script in remote_scripts] + [
            'echo "%s %s/%s" >> crontab.txt' % (interval, home, remote_script)
            for remote_script in remote_scripts] + [
            'crontab crontab.txt',
            'rm crontab.txt'])

def configure_analysis(cx, remote_scripts):
    local_scripts = [
        os.path.join(cx.root_dir, 'scripts', script)
        for script in remote_scripts]

    for local_script, remote_script in zip(local_scripts, remote_scripts):
        remote_copy(cx, local_script, remote_script)
    remote_commands(cx, [
            'chmod 755 %s' % remote_script
            for remote_script in remote_scripts])

configurations = {
    # Name: [Function, Required Parameters, Variadic]
    "tmp": [configure_tmp, 0, False],
    "pip_install": [configure_pip_install, 1, False],
    "cuda_base": [configure_cuda_base, 0, False],
    "cuda_full": [configure_cuda_full, 0, False],
    "timezone": [configure_timezone, 0, False],
    "ssh_server": [configure_ssh_server, 0, False],
    "krb5_server": [configure_krb5_server, 0, False],
    "krb5_client": [configure_krb5_client, 0, False],
    "terminate_krb5_client": [configure_terminate_krb5_client, 0, False],
    "ldap_server": [configure_ldap_server, 0, False],
    "ldap_client": [configure_ldap_client, 0, False],
    "nfs_server": [configure_nfs_server, 0, False],
    "nfs_client": [configure_nfs_client, 0, False],
    "torque_server": [configure_torque_server, 1, False],
    "torque_client": [configure_torque_client, 0, False],
    "terminate_torque_client": [configure_terminate_torque_client, 0, False],
    "spark_base": [configure_spark_base, 0, False],
    "spark_server": [configure_spark_server, 0, False],
    "spark_client": [configure_spark_client, 0, False],
    "spark_dataset": [configure_spark_dataset, 1, False],
    "spark_torque_client": [configure_spark_torque_client, 0, False],
    "terminate_spark_torque_client": [
        configure_terminate_spark_torque_client, 0, False],
    "skeleton": [configure_skeleton, 0, False],
    "monitoring": [configure_monitoring, 2, False],
    "analysis": [configure_analysis, 1, False],
}

def configure(cx, config_name, *config_args):
    if config_name not in configurations:
        raise Exception('Invalid configuration "%s"' % config_name)
    config_fn, config_nargs, config_variadic = configurations[config_name]
    if config_variadic:
        assert len(config_args) >= config_nargs
    else:
        assert len(config_args) == config_nargs
    config_fn(cx, *config_args)

###
### Handlers
###

def handle_package(cx, package_list):
    install_packages(cx, package_list)

def handle_configure(cx, name, *args):
    configure(cx, name, *args)

handlers = {
    # Name: [Function, Required Parameters, Variadic]
    "package": [handle_package, 1, False],
    "configure": [handle_configure, 1, True],
}

def handle(cx, handler_name, *handler_args):
    if handler_name not in handlers:
        raise Exception('Invalid handler "%s"' % config_name)
    handler_fn, handler_nargs, handler_variadic = handlers[handler_name]
    if handler_variadic:
        assert len(handler_args) >= handler_nargs
    else:
        assert len(handler_args) == handler_nargs
    handler_fn(cx, *handler_args)

###
### Modules
###

def install_module(cx, module):
    module_config = cx.config['Modules'][module]
    for command in module_config['Commands']:
        handle(cx, *command)

###
### Drivers
###

def driver_init_connection(cx):
    cx.connection = connect(cx)

    cx.key_filename = os.path.join(
        cx.root_dir,
        '%s.pem' % cx.secret['Course Number'])
    cx.key_name = cx.secret['Course Number']
    create_key(cx, cx.key_name, cx.key_filename)

    cx.security_group = cx.secret['Course Number']
    create_security_group(cx, cx.security_group)

def driver_init_cluster_state(cx, cluster_name, cluster_type, parent):
    if cluster_name not in cx.state['clusters']:
        if parent is not None:
            assert parent in cx.state['clusters']
            cx.state['clusters'][parent]['clusters'][cluster_name] = None
        cx.state['clusters'][cluster_name] = collections.OrderedDict([
            ('cluster_type', cluster_type),
            ('parent', parent),
            ('nodes', collections.OrderedDict()),
            ('clusters', collections.OrderedDict()),
            ('features', collections.OrderedDict()),
        ])
    return cx.new_cluster_scope(cluster_name)

def driver_validate_requirements(cx, modules):
    additional = {}
    for module in modules:
        if module not in cx.config['Modules']:
            raise Exception('Error: Invalid module "%s"' % module)
        module_config = cx.config['Modules'][module]
        for require in module_config['Requires']:
            if find_feature(cx, require, True, additional) is None:
                raise Exception(
                    'Feature "%s" required by "%s" not available' % (
                        require, module))
        for provide in module_config['Provides']:
            if find_feature(cx, provide, False, additional) is not None:
                raise Exception(
                    'Feature "%s" provided by "%s" already available' % (
                        provide, module))
            add_feature(cx, provide, additional)

def driver_create_instances_helper(cx, node_requests):
    node_configs = [
        (count, node_type, initial_image, cx.config['Nodes'][node_type])
        for count, node_type, initial_image in node_requests]

    all_instances = []
    for count, node_type, initial_image, node_config in node_configs:
        # Create new instance.
        all_instances.append(
            (node_type,
             create_instance(
                 cx,
                 count,
                 node_config['Instance Type'],
                 (node_config['AMI'][cx.secret['AWS Region']]
                  if initial_image else cx.state['images'][node_type]),
                 node_config['Volume Size (GiB)'],
                 (node_config['Disable API Termination']
                  if not initial_image else False),
                 '%s %s %s' % (cx.state['recipe'], cx.cluster_name, node_type))))

    for node_type, node_type_instances in all_instances:
        for instance in node_type_instances:
            keys = save_instance_host_keys(cx, instance)

            cx.state['nodes'][instance.id] = collections.OrderedDict([
                ('node_type', node_type),
                ('cluster_name', cx.cluster_name),
                ('public_dns_name', instance.public_dns_name),
                ('private_dns_name', instance.private_dns_name),
                ('host_keys', keys),
            ])
            cx.state['clusters'][cx.cluster_name]['nodes'][instance.id] = None

            # Wait for shell prompt.
            cx = cx.new_node_scope(instance.id)
            wait_for_remote_shell(cx)

    return zip(*all_instances)[1]

def driver_create_image_helper(cx, node_type, instance):
    node_config = cx.config['Nodes'][node_type]
    cx = cx.new_node_scope(instance.id)

    protect_directory(cx, '/home/ubuntu')

    for module in node_config['Image Modules']:
        install_module(cx, module)

    stop_instance(cx, instance)
    node_image = create_image(
        instance,
        '%s_%s_%s' % (
            cx.secret['Course Number'],
            cx.secret['Assignment Number'],
            node_type))
    terminate_instance(cx, instance)

    del cx.state['nodes'][instance.id]
    del cx.state['clusters'][cx.cluster_name]['nodes'][instance.id]

    cx.state['images'][node_type] = node_image

    return node_image

def driver_create_node_helper(cx, node_type, instance):
    node_config = cx.config['Nodes'][node_type]
    cx = cx.new_node_scope(instance.id)

    for module in node_config['Instance Modules']:
        install_module(cx, module)

def driver_create_node(cx, node_type):
    node_config = cx.config['Nodes'][node_type]
    driver_validate_requirements(cx, node_config['Instance Modules'])

    node_requests = [(1, node_type, False)]
    (instance,), = driver_create_instances_helper(cx, node_requests)
    driver_create_node_helper(cx, node_type, instance)

    print 'Instance ready "%s"' % instance.id

def gensym(prefix, existing):
    for i in itertools.count(0):
        name = '%s%s' % (prefix, i)
        if name not in existing:
            return name

def driver_create_cluster(cx, cluster_type):
    cluster_config = cx.config['Clusters'][cluster_type]

    cluster_name = gensym('c', cx.state['clusters'])
    cx = driver_init_cluster_state(
        cx, cluster_name, cluster_type, cx.cluster_name)

    node_types = zip(*cluster_config['Nodes'])
    node_requests = zip(*(node_types + [itertools.repeat(False)]))
    all_instances = driver_create_instances_helper(cx, node_requests)
    for node_type, node_type_instances in zip(node_types[1], all_instances):
        for instance in node_type_instances:
            driver_create_node_helper(cx, node_type, instance)

    for module in cluster_config['Modules']:
        install_module(cx, module)

    print 'Cluster ready "%s"' % cluster_name

def driver_init_recipe(cx, recipe):
    recipe_config = cx.config['Recipes'][recipe]

    cx.state['recipe'] = recipe

    # Collect list of required node types.
    node_types = set()
    for elt_type in recipe_config['Enable']:
        if elt_type in cx.config['Nodes']:
            node_types.add(elt_type)
        elif elt_type in cx.config['Clusters']:
            node_types.update(
                zip(*cx.config['Clusters'][elt_type]['Nodes'])[1])
        else:
            assert False

    # Skip any node types already prepared.
    node_types = node_types - set(cx.state['images'].iterkeys())

    if len(node_types) == 0:
        print 'Nothing to do'
        return

    # Construct a requests for the required node types.
    node_requests = []
    for node_type in node_types:
        node_config = cx.config['Nodes'][node_type]
        driver_validate_requirements(cx, node_config['Image Modules'])

        node_requests.append((1, node_type, True))

    # Create nodes.
    instances = zip(*driver_create_instances_helper(cx, node_requests))[0]

    # Create images from nodes.
    for node_type, instance in zip(node_types, instances):
        node_image = driver_create_image_helper(cx, node_type, instance)

        # Hack: If we crash at this point don't lose all the state.
        cx.persist_state()

        print 'Image ready for "%s" "%s"' % (node_type, node_image)

def driver_terminate_node_helper(cx):
    node_config = cx.config['Nodes'][cx.node['node_type']]

    # Terminate modules
    for module in node_config['Terminate Modules']:
        install_module(cx, module)

    # Terminate node
    instance = get_instance(cx, cx.node_name)
    terminate_instance(cx, instance)

    # Cleanup state
    del cx.state['nodes'][cx.node_name]
    for cluster in cx.state['clusters'].itervalues():
        if cx.node_name in cluster['nodes']:
            del cluster['nodes'][cx.node_name]

def driver_terminate_node(cx, node_name):
    choices = cx.state['nodes']
    print 'The following nodes are currently running:'
    for name, node in choices.iteritems():
        print '%s (%s)' % (name, node['node_type'])
    print 'Which node would you like to terminate?'

    first = True
    while True:
        if not first or node_name is None:
            node_name = raw_input('Node? ')
        first = False
        if node_name not in choices:
            print 'Please try a different node.'
            continue
        has_features = False
        for cluster in cx.state['clusters'].itervalues():
            for feature, feature_state in cluster['features'].iteritems():
                if feature_state['node'] == node_name:
                    print 'Error: This node provides "%s".' % feature
                    has_features = True
        if has_features:
            print 'Please try a different node.'
            continue
        break

    node_cx = cx.new_node_scope(node_name)
    driver_terminate_node_helper(node_cx)

def driver_terminate_cluster_helper(cx):
    cluster_config = cx.config['Clusters'][cx.cluster['cluster_type']]

    # Terminate cluster modules
    for module in cluster_config['Terminate Modules']:
        install_module(cx, module)

    # Terminate nodes
    for node in cx.cluster['nodes'].iterkeys():
        node_cx = cx.new_node_scope(node)
        driver_terminate_node_helper(node_cx)

    # Cleanup state
    del cx.state['clusters'][cx.cluster_name]
    for cluster in cx.state['clusters'].itervalues():
        if cx.node_name in cluster['clusters']:
            del cluster['clusters'][cx.cluster_name]

def driver_terminate_cluster(cx, cluster_name):
    choices = cx.state['clusters']
    print 'The following clusters are currently running:'
    for name, cluster in choices.iteritems():
        print '%s (%s)' % (name, cluster['cluster_type'])
    print 'Which node would you like to terminate?'

    first = True
    while True:
        if not first or cluster_name is None:
            cluster_name = raw_input('Cluster? ')
        first = False
        if cluster_name not in choices:
            print 'Please try a different cluster.'
            continue
        if cluster['parent'] is None:
            print 'Error: Unable to terminate root cluster.'
            print 'Please try a different node.'
            continue
        break

    cluster_cx = cx.new_cluster_scope(cluster_name)
    driver_terminate_cluster_helper(cluster_cx)

def driver_create_user_helper(cx, username, fullname, given_name, surname):
    # Choose a UID and password.
    password = base64.b64encode(os.urandom(12))
    uid = cx.state['next_available_uid']
    cx.state['next_available_uid'] += 1

    print password
    create_user(cx, username, password, fullname, given_name, surname, uid)

    # TODO(shoumik): This may no longer be necessary.
    for cluster_name in cx.state['clusters'].iterkeys():
        cluster_cx = cx.new_cluster_scope(cluster_name)
        spark_feature = find_feature(cluster_cx, 'spark', recursive = False)
        if spark_feature is not None:
            master_cx = cluster_cx.new_node_scope(spark_feature['node'])

    cx.state['users'][username] = collections.OrderedDict([
        ('username', username),
        ('fullname', fullname),
        ('given_name', given_name),
        ('surname', surname),
        ('password', password),
        ('uid', uid),
    ])

def driver_create_user(cx):
    ldap_feature = find_feature(cx, 'ldap')
    cx = cx.new_node_scope(ldap_feature['node'])

    username = ''
    while True:
        username = raw_input('Username? ')
        if len(username) == 0 or not is_username_available(cx, username):
            print 'Please try a different username.'
            continue
        break
    given_name = raw_input('Given Name? ')
    surname = raw_input('Surname? ')
    fullname = ' '.join([given_name, surname])

    driver_create_user_helper(cx, username, fullname, given_name, surname)

def driver_import_roster(cx):
    ldap_feature = find_feature(cx, 'ldap')
    cx = cx.new_node_scope(ldap_feature['node'])

    roster_filename = ''
    while True:
        roster_filename = raw_input('Roster filename? ')
        if len(roster_filename) == 0 or not os.path.exists(roster_filename):
            print 'Please try a different filename.'
            continue
        break

    # Parse CSV file and identify header and body.
    with open(roster_filename, 'rb') as f:
        content = list(csv.reader(f))
    header = content[0]
    body = zip(*content[1:])

    # Find columns for name and email.
    first_name_index = header.index('First Name')
    last_name_index = header.index('Last Name')
    email_index = header.index('Email')

    # Extract column data.
    first_names = body[first_name_index]
    last_names = body[last_name_index]
    emails = body[email_index]

    # Check that usernames are unique and valid.
    usernames = [email[:email.index('@')] for email in emails]
    assert len(usernames) == len(set(usernames))
    assert 'root' not in usernames
    assert 'ubuntu' not in usernames

    # Create users.
    for username, first_name, last_name in zip(usernames, first_names, last_names):
        fullname = first_name + " " + last_name
        print 'Creating account %s for %s...' % (username, fullname)
        driver_create_user_helper(cx, username, fullname, first_name, last_name)

def driver_email_helper(credentials, from_address, to_address,
                        reply_to_address, subject, body):
    smtp_server, smtp_username, smtp_password = credentials

    message = email.MIMEText.MIMEText(body)

    message['Subject'] = subject
    message['From'] = from_address
    message['To'] = to_address
    message.add_header('reply-to', reply_to_address)

    server = smtplib.SMTP(smtp_server)
    server.ehlo()
    server.starttls()
    server.ehlo()
    server.login(smtp_username, smtp_password)
    server.sendmail(from_address, [to_address], message.as_string())
    server.quit()

def driver_email_roster(cx):
    ldap_feature = find_feature(cx, 'ldap')
    cx = cx.new_node_scope(ldap_feature['node'])

    roster_filename = ''
    while True:
        roster_filename = raw_input('Roster filename? ')
        if len(roster_filename) == 0 or not os.path.exists(roster_filename):
            print 'Please try a different filename.'
            continue
        break

    credentials = list(query_json(collections.OrderedDict([
        ('SMTP Server', 'smtp.gmail.com:587'),
        ('SMTP Username', 'username'),
        ('SMTP Domain', 'gmail.com'),
        ('SMTP Password', ''),
    ])).itervalues())
    from_address = '%s@%s' % (credentials[1], credentials[2])
    credentials = [credentials[0], credentials[1], credentials[3]]
    reply_to_address = cx.secret['Course Staff Email']

    # Parse CSV file and identify header and body.
    with open(roster_filename, 'rb') as f:
        content = list(csv.reader(f))
    header = content[0]
    body = zip(*content[1:])

    # Find columns for name and email.
    email_index = header.index('Email')

    # Extract column data.
    emails = body[email_index]

    roster_emails = dict(
        (email[:email.index('@')], email) for email in emails)
    pending_users = dict(
        item for item in cx.state['users'].iteritems()
        if 'password' in item[1])
    usernames_to_email = list(
        set(roster_emails.iterkeys()) & set(pending_users.iterkeys()))

    max_emails = 80

    print
    print 'There are %s unsent emails.' % len(usernames_to_email)
    print
    if len(usernames_to_email) > max_emails:
        print 'Note: Gmail only allows %s sent emails per hour.' % max_emails
        print 'Please run this command again after an hour to continue.'
        print
        usernames_to_email = usernames_to_email[:max_emails]

    print 'Warning: About to send %s emails.' % len(usernames_to_email)
    cont = False
    while True:
        cont = raw_input('Continue? ')
        if cont.lower() == 'yes':
            cont = True
            break
        if cont.lower() == 'no':
            cont = False
            break
        print 'Yes or no please.'
    if not cont: return

    email_template_filename = os.path.join(
        cx.root_dir, 'email', 'account_email.txt')
    with open(email_template_filename, 'rb') as f:
        email_template = f.read()

    print 'Sent the following emails:'
    for username in usernames_to_email:
        user = pending_users[username]
        to_address = roster_emails[username]
        substitutions = {
            'assignment_number': cx.secret['Assignment Number'],
            'assignment_number_lower': cx.secret['Assignment Number'].lower(),
            'first_name': user['given_name'],
            'username': username,
            'password': user['password'],
            'head_node_name': cx.hostname,
            'reply_to_address': reply_to_address,
            'course_number': cx.secret['Course Number'].upper(),
            'course_assistant_names': cx.secret['Course Assistant Names'],
        }
        subject = '[%s] %s Account' % (
            cx.secret['Course Number'],
            cx.secret['Assignment Number'])
        email_body = email_template.format(**substitutions)
        driver_email_helper(
            credentials, from_address, to_address,
            reply_to_address, subject, email_body)
        del cx.state['users'][username]['password']
        cx.persist_state()
        print to_address

def driver(root_dir, argv):
    parser = argparse.ArgumentParser(
        description = 'Manage Amazon EC2 compute resources.')
    parser.add_argument('action', choices = (
        'create_node',
        'create_cluster',
        'create_user',
        'init',
        'terminate_node',
        'terminate_cluster',
        'import_roster',
        'email_roster'))
    parser.add_argument('target', nargs = '?')
    args = parser.parse_args(argv[1:])

    cx = Context(root_dir)
    driver_init_connection(cx)
    cx = driver_init_cluster_state(cx, "top", None, None)

    if args.action == 'init':
        if args.target not in cx.config['Recipes']:
            raise Exception('Invalid recipe "%s"' % args.target)
        if cx.state['recipe'] is not None and cx.state['recipe'] != args.target:
            raise Exception('Recipe "%s" already configured' % (
                cx.state['recipe']))
        driver_init_recipe(cx, args.target)
    elif args.action == 'create_node':
        if args.target not in cx.config['Nodes']:
            raise Exception('Invalid node type "%s"' % args.target)
        if cx.state['recipe'] is None:
            raise Exception('Initialize a recipe first')
        if args.target not in cx.config['Recipes'][cx.state['recipe']]['Enable']:
            raise Exception('Node type "%s" is not enabled for recipe "%s"' % (
                args.target, cx.state['recipe']))
        driver_create_node(cx, args.target)
    elif args.action == 'create_cluster':
        if args.target not in cx.config['Clusters']:
            raise Exception('Invalid cluster type "%s"' % args.target)
        if cx.state['recipe'] is None:
            raise Exception('Initialize a recipe first')
        if args.target not in cx.config['Recipes'][cx.state['recipe']]['Enable']:
            raise Exception(
                'Cluster type "%s" is not enabled for recipe "%s"' % (
                    args.target, cx.state['recipe']))
        driver_create_cluster(cx, args.target)
    elif args.action == 'create_user':
        if cx.state['recipe'] is None:
            raise Exception('Initialize a recipe first')
        if find_feature(cx, 'ldap') is None:
            raise Exception('LDAP feature is unavailable')
        driver_create_user(cx)
    elif args.action == 'terminate_node':
        driver_terminate_node(cx, args.target)
    elif args.action == 'terminate_cluster':
        driver_terminate_cluster(cx, args.target)
    elif args.action == 'import_roster':
        if cx.state['recipe'] is None:
            raise Exception('Initialize a recipe first')
        if find_feature(cx, 'ldap') is None:
            raise Exception('LDAP feature is unavailable')
        driver_import_roster(cx)
    elif args.action == 'email_roster':
        driver_email_roster(cx)
    else:
        assert False

    cx.persist_state()

if __name__ == '__main__':
    driver(os.path.dirname(os.path.realpath(__file__)), sys.argv)
