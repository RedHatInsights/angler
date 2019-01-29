# Resource Updater [WIP]

The idea behind Angler is to provide for a pod that can run and catch webooks
from various repos and autoupdate that resource in Openshift.

# General Workflow

1. Master branch is updated either directly or via PR
2. Webhook is sent to Angler on a custom URL
3. Angler inspects the payload to find files it cares about
4. Angler downloads the file
5. Angler pushes changes to the openshift API

Files that are downloaded can be either actual openshift yaml, or raw data. This can
be useful if there is a format of a file you want to ingest as a configMap but do not
have an automated process that actually creates a configmap from the data.

Currently, Angler can update resources within the Openshift Insights development cluster
because that is where it resides. In order to enable the service to update resources in your
project, you must give `edit` access to `system:serviceaccount:angler:angler`

# TODO

* enable updating of other openshift resources. Currently only setup for configMaps