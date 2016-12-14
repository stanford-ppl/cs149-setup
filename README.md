This is the setup tool used for managing the AWS infrastructure for
*CS 149: Parallel Computing* at Stanford University, taught by Alex
Aiken and Kunle Olukotun.

CS 149 includes programming assignments covering
[threads](https://class.stanford.edu/c4x/Engineering/CS149/asset/pa1.pdf),
[STM](https://class.stanford.edu/c4x/Engineering/CS149/asset/pa2.pdf),
[MapReduce
(Hadoop)](https://class.stanford.edu/c4x/Engineering/CS149/asset/pa3.pdf),
[OpenMP](https://class.stanford.edu/c4x/Engineering/CS149/asset/pa4.pdf),
and [GPUs
(CUDA)](https://class.stanford.edu/c4x/Engineering/CS149/asset/pa5.pdf). Each
assignment runs on a distinct hardware/software platform, requiring
significant administrative effort. This tool was created in 2013 and
2014 by Elliott Slaughter (TA and advisee of Alex Aiken) to automate
the management of AWS infrastructure.

The default configuration for CS 149 uses a star topology with a
single head node and multiple compute nodes. The head node provides an
SSH endpoint and Kerberos, LDAP, and NFS. Torque is used to moderate
access to the compute nodes. For consistency, we do this even for
Hadoop, where the compute "nodes" are sub-clusters with a single
NameNode/JobTracker master node and a number of DataNode/TaskTracker
slave nodes.

The tool can, of course, be configured to use other topologies and
different technologies.

*IMPORTANT*: Before using the setup tool in production, be sure to
read and understand the section on security, below.

# Dependencies

The setup tool requires:

  * Python >= 2.7 and < 3.0 with the following libraries:

      * Boto (https://github.com/boto/boto)

  * An AWS account (https://aws.amazon.com/) with the following IAM users:

      * EC2 with read-write privileges

      * S3 with read-only privileges (optional)

# Basic Usage

To configure an assignment, make a fresh clone of the setup tool and run:

    ./setup.py init <recipe> # e.g. pa2

This will query the user for various course metadata, and create keys,
security groups, and images on EC2. After this completes, create one
or more nodes or clusters with the commands:

    ./setup.py create_node <node_type> # e.g. head
    ./setup.py create_cluster <cluster_type> # e.g. hadoop_cluster

Nodes and clusters can be terminated with the commands:

    ./setup.py terminate_node [<node_id>] # prompts if unspecified
    ./setup.py terminate_cluster [<cluster_id>] # prompts if unspecified

Users can be created individually or imported from a roster:

    ./setup.py create_user # prompts for username
    ./setup.py import_roster # prompts for roster file

The roster must be a CSV file with the following columns:

    ID,Last Name,First Name,Email

Users can be notified of their accounts via email (SMTP):

    ./setup.py email_roster # prompts for roster file

# Configuration

The default configuration provides everything necessary to replicate
our setup for CS 149. For customized setup, there are two relevant
source files:

  * `config/config.json`: Contains the configuration for the tool.
  * `setup.py`: The actual source for the tool.

Simple changes (like installing additional Ubuntu packages, or
changing the number or type of nodes in a Hadoop cluster) can
generally be made to the `config.json` file. More complicated changes
(like introducing an entirely new technology such as MPI) may require
changes to `setup.py` as well.

Both `config.json` and `setup.py` share a common set of abstractions
described below.

## Modules

A module in the context of this tool encapsulates the setup required
for a certain piece of functionality. For example, a module might
install a baseline list of packages common to all node types. Or a
module might configure a Kerberos server, or a Kerberos client.

A module consists of a list of commands, and provided and required
features. Features are described below. The commands for a module are
defined within `setup.py`, and will be executed within the context a
certain node or cluster. Each node and cluster type provides a list of
modules required for that type.

## Features

Features represent network services available in a cluster. For
example, a module which configures a Kerberos server may register the
feature `krb5` so that any node which wishes to use the Kerberos
client module will know where the server is located.

Features may be provided or required for certain node types. The setup
tool ensures that a given feature is available on at most one node in
a cluster, and that any required features are present before creating
nodes which depend on that feature.

Features are scoped to clusters, so different clusters which provide
the same feature do not interfere with one another.

## Nodes

A node is an EC2 instance. Nodes are configured from node types listed
in `config.json`, where each node type contains various metadata (what
AMI and instance type to use, etc.) and three lists of modules: image
modules, instance modules, and terminate modules.

  * Image modules are used when initializing an AMI for the node
    type. Typical image modules install lists of packages and
    configure software which do not depend on instance-specific
    details.

  * Instance modules are used when configuring a node which has been
    newly booted from the AMI for the node type. Instance modules are
    responsible for the final configuration of a node, such as adding
    the node to the list of Torque compute nodes in a cluster.

  * Terminate modules are used before terminating a node. For example,
    a Torque compute node might need to be marked offline to ensure
    that any running jobs are completed before terminating the node.

## Clusters

Clusters are hierarchical collections of nodes and clusters. The root
of the cluster tree is a system-defined cluster named `top`. Nodes and
clusters created by the user are automatically placed into `top`.

Clusters, like nodes, are configured from cluster types listed in
`config.json`, which consist of a list of nodes to instantiate into
the cluster, a list of cluster-level initialization modules, and a
list of termination modules. The initialization modules for a cluster
are run after all of the nodes have been configured, and can be used,
for example, to load a dataset on to a Hadoop cluster. The termination
modules for a cluster are run before any of the termination modules
for the individual nodes.

## Recipes

Recipes consist of lists of node and cluster types. Recipes are
intended to correspond to assignments, where typically one wants to
only create node and cluster types relevant to current
assignment. Recipes help avoid typos by reporting errors if the user
requests a node or cluster type not listed for the active recipe.

Recipes can be activated by the `setup.py init` command. Activation
does two things:

  * The tool scans the list of nodes and clusters and initializes AMIs
    for the required node types.

  * The tool sets the active recipe so that node and cluster types can
    be checked against the list for that recipe.

# Security

While some effort has been to provide a minimal level of security,
this tool should *NOT* be used for important production systems
without a thorough security review.

Specifically, Amazon EC2 is an entropy-starved platform, which makes it
difficult to gather enough randomness to satisfy Kerberos during the
initial KDC creation process. To avoid waiting a very long time for
entropy to accumulate, the tool circumvents the random number
generator. This significantly undermines the strength of the
cryptography used by the system.

Otherwise, the default security is not unreasonable. An EC2 security
group is used to ensure that the only outward-facing port is 22 (SSH),
although the security group is entirely open internally. LDAP uses
Kerberos for security. NFS is currently insecure (because NFSv4 with
Kerberos did not play nicely with Torque), but if you trust Amazon
with your data in the first place then there's not much you can do
about that.

# Acknowledgements

Usage of AWS for CS 149 at Stanford was funded by an AWS in Education
Coursework Grant. For more information on Amazon's grant program, see:

https://aws.amazon.com/grants/

# License

Copyright (c) 2014, Stanford University

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
