# Resource Updater [WIP]

The idea behind Angler is to provide for a pod that can run and catch webooks
from various repos and autoupdate that resource in Openshift.

# General Workflow

1. PR is merged to master contain a new Openshift resource update
2. Webhook is sent to Angler
3. Angler inspects the payload to find files it cares about
4. Angler downloads update
5. Angler pushes changes to the openshift API

# TODO

This should be capabale of handling multiple resource types and work across multiple
projects and clusters. Currently, it will only update configmaps that reside in the
platform-ci project. This should have multiple endpoints that all perform different
tasks and can update various files/resources based on webhooks.

At this point, it's mainly a proof of concept.