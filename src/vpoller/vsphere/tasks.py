import inspect
import datetime
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import pyVmomi
import random
import re
import socket
import struct
import sys
import time
import types
from vpoller.log import logger
from vpoller.task.decorators import task
import vpoller.vsphere.tasks

# replacement of get_object_by_property on vconnector core.py as it sucks at building cache
from vconnector.core import VConnector
from vconnector.cache import CachedObject

import vsan
import vsanmgmtObjects


def get_object_by_property_cache_all(self, property_name, property_value, obj_type):
    """
    Find a Managed Object by a propery

    If cache is enabled then we search for the managed object from the
    cache first and if present we return the object from cache.

    Args:
        property_name            (str): Name of the property to look for
        property_value           (str): Value of the property to match
        obj_type       (pyVmomi.vim.*): Type of the Managed Object

    Returns:
        The first matching object

    """
    # logging.info('ALL YOUR METHODS ARE BELONG TO ME !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
    if not issubclass(obj_type, pyVmomi.vim.ManagedEntity):
        raise VConnectorException('Type should be a subclass of vim.ManagedEntity')

    if self.cache_enabled:
        cached_obj_name = '{}:{}'.format(obj_type.__name__, property_value)
        if cached_obj_name in self.cache:
            logging.debug('Using cached object %s', cached_obj_name)
            return self.cache.get(cached_obj_name)

    # logging.info('Looking up object %s', cached_obj_name)
    view_ref = self.get_container_view(obj_type=[obj_type])
    props = self.collect_properties(
        view_ref=view_ref,
        obj_type=obj_type,
        path_set=[property_name],
        include_mors=True
    )
    view_ref.DestroyView()

    obj = None
    for each_obj in props:
        obj = None

        if self.cache_enabled:
            if each_obj.get(property_name) is not None:
                cached_obj_key = '{}:{}'.format(obj_type.__name__, each_obj[property_name])
            else:
                cached_obj_key = None

        if cached_obj_key is not None and cached_obj_key not in self.cache:
            obj = each_obj['obj']
            cached_obj = CachedObject(
                name=cached_obj_key,
                obj=obj,
                ttl=self.cache_ttl
            )
            self.cache.add(obj=cached_obj)

        if each_obj.get(property_name) == property_value:
            break
        else:
            obj = None

    return obj


logging.info(
    'Overriding Vconnector.get_object_by_property method with tasks_extension.py get_object_by_property_cache_all')
VConnector.get_object_by_property = get_object_by_property_cache_all


def _entity_perf_metrics_get(agent, entity, counter_name, max_sample=1, instance='', interval_name=None):
    """
    Retrieve performance metrics from a managed object

    Args:
        agent         (VConnector): A VConnector instance
        entity     (pyVmomi.vim.*): A managed entity (performance provider)
        counter_name         (str): A performance counter name
        max_sample           (int): Max samples to be retrieved
        instance             (str): Instance name, e.g. 'vmnic0'
        perf_interval_name   (str): Historical performance interval name

    Returns:
        The collected performance metrics from the managed object

    """
    logger.info(
        '[%s] Retrieving performance metrics %s for %s',
        agent.host,
        counter_name,
        entity.name,
    )

    provider_summary = agent.si.content.perfManager.QueryPerfProviderSummary(
        entity=entity
    )

    logger.debug(
        '[%s] Entity %s supports real-time statistics: %s',
        agent.host,
        entity.name,
        provider_summary.currentSupported
    )
    logger.debug(
        '[%s] Entity %s supports historical statistics: %s',
        agent.host,
        entity.name,
        provider_summary.summarySupported
    )

    if not provider_summary.currentSupported and not interval_name:
        logger.warning(
            '[%s] No historical performance interval provided for entity %s',
            agent.host,
            entity.name
        )
        return {'success': 1, 'msg': 'No historical performance interval provided for entity {}'.format(entity.name)}

    # For real-time statistics use the refresh rate of the provider.
    # For historical statistics use one of the existing historical
    # intervals on the system.
    # For managed entities that support both real-time and historical
    # statistics in order to retrieve historical stats a valid
    # interval name should be provided.
    # By default we expect that the requested performance counters
    # are real-time only, so if you need historical statistics
    # make sure to pass a valid historical interval name.
    if interval_name:
        if interval_name not in [i.name for i in agent.perf_interval]:
            logger.warning(
                '[%s] Historical interval %s does not exists',
                agent.host,
                interval_name
            )
            return {'success': 1, 'msg': 'Historical interval {} does not exists'.format(interval_name)}
        else:
            interval_id = [i for i in agent.perf_interval if i.name == interval_name].pop().samplingPeriod
    else:
        interval_id = provider_summary.refreshRate

    metric_ids = []
    metric_id_map = {}
    for cn in counter_name.split(','):
        counter_info = vpoller.vsphere.tasks._get_counter_by_name(
            agent=agent,
            name=cn
        )

        if not counter_info:
            return {
                'success': 1,
                'msg': 'Unknown performance counter requested'
            }

        metric_id = pyVmomi.vim.PerformanceManager.MetricId(
            counterId=counter_info.key,
            instance=instance
        )

        metric_ids.append(metric_id)
        metric_id_map[metric_id.counterId] = cn

    # startTime=datetime.datetime.now(pytz.timezone('US/Eastern'))-datetime.timedelta(minutes=5)
    if provider_summary.currentSupported:
        query_spec = pyVmomi.vim.PerformanceManager.QuerySpec(
            maxSample=max_sample,
            entity=entity,
            metricId=metric_ids,
            intervalId=interval_id
        )

    else:
        # vcenter seems to be a bit behind here to double up the interval to ensure we get some data
        # should never get 2 values, but if we do, it'll focus down later on
        startTime = datetime.datetime.now() - datetime.timedelta(minutes=(interval_id / 60 * 2))
        query_spec = pyVmomi.vim.PerformanceManager.QuerySpec(
            maxSample=max_sample,
            entity=entity,
            metricId=metric_ids,
            startTime=startTime,
            intervalId=interval_id
        )

    data = agent.si.content.perfManager.QueryPerf(
        querySpec=[query_spec]
    )

    result = []
    result_latest = {}
    for sample in data:
        sample_info, sample_value = sample.sampleInfo, sample.value
        for value in sample_value:
            if instance != '*' or value.id.instance != '':
                for s, v in zip(sample_info, value.value):
                    d = {
                        'interval': s.interval,
                        'timestamp': str(s.timestamp),
                        'counterId': metric_id_map[value.id.counterId],
                        'instance': value.id.instance,
                        'value': v
                    }
                    result.append(d)

                    key_latest = str(value.id.instance) + str(metric_id_map[value.id.counterId])
                    prev = result_latest.get(key_latest)
                    if prev is not None:
                        if datetime.datetime.strptime(prev['timestamp'],
                                                      '%Y-%m-%d %H:%M:%S+00:00') < datetime.datetime.strptime(
                                d['timestamp'], '%Y-%m-%d %H:%M:%S+00:00'):
                            result_latest[key_latest] = d
                    else:
                        result_latest[key_latest] = d

    # TODO: add an option to focus to only most recent rather than hard coded here
    result2 = []
    for k, v in result_latest.iteritems():
        result2.append(v)

    r = {
        'msg': 'Successfully retrieved performance metrics',
        'success': 0,
        'result': result2,
    }

    return r


def pool_type(pool_name):
    pool_type = 99  # unknown
    if re.match('^...........C', pool_name) or re.match('^...........K', pool_name) or re.match('^...........I',
                                                                                                pool_name):
        pool_type = 1  # core
    elif re.match('^...........B', pool_name) or re.match('^...........H', pool_name) or re.match('^...........J',
                                                                                                  pool_name):
        pool_type = 0  # basic

    return pool_type


@task(name='resource.pool.get', required=['name', 'properties'])
def resource_pool_get(agent, msg):
    """
    Get properties of a single vim.ResourcePool managed object

    Example client message would be:

    {
        "method":     "resource.pool.get",
        "hostname":   "vc01.example.org",
        "name":       "MyResourcePool",
        "properties": [
            "name",
            "runtime.cpu",
            "runtime.memory",
            "runtime.overallStatus"
        ]
    }

    Returns:
        The managed object properties in JSON format

    """
    # Property names to be collected
    properties = ['name']
    if 'properties' in msg and msg['properties']:
        properties.extend(msg['properties'])

    properties_readd = []
    if 'pool.type' in properties:
        properties_readd.append('pool.type')
        properties.remove('pool.type')

    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=properties,
        obj_type=pyVmomi.vim.ResourcePool,
        obj_property_name='name',
        obj_property_value=msg['name']
    )

    properties.extend(properties_readd)

    if data.get('result') is not None:
        if 'pool.type' in properties:
            data['result'][0]['pool.type'] = pool_type(msg['name'])

    return data


@task(name='vm.get', required=['name', 'properties'])
def vm_get(agent, msg):
    """
    Get properties for a vim.VirtualMachine managed object
    Example client message would be:
        {
            "method":     "vm.get",
            "hostname":   "vc01.example.org",
            "name":       "vm01.example.org",
            "properties": [
                "name",
                "runtime.powerState"
            ]
        }
    Returns:
        The managed object properties in JSON format
    """

    # temporary no-op for rollout switing to instaneUUID instead of name
    # return {'success': 1, 'msg': 'temporary disable for rollout'}

    # Property names to be collected
    properties = ['name', 'config.instanceUuid']
    if 'properties' in msg and msg['properties']:
        properties.extend(msg['properties'])

    properties_readd = []
    if 'vm.type' in properties:
        properties_readd.append('vm.type')
        properties.remove('vm.type')

    # force resource pool... needed for vm.type and for customer tagging
    if 'resourcePool' not in properties:
        properties.extend(['resourcePool'])

    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=properties,
        obj_type=pyVmomi.vim.VirtualMachine,
        obj_property_name='config.instanceUuid',
        obj_property_value=msg['name']
    )

    properties.extend(properties_readd)

    if data.get('result') is not None:
        if 'runtime.host' in properties:
            runtime_host = data['result'][0].get('runtime.host')
            if runtime_host is not None:
                data['result'][0]['runtime.host'] = runtime_host.name
            else:
                data['result'][0]['runtime.host'] = ''

        if 'resourcePool' in properties:
            resource_pool = data['result'][0].get('resourcePool')
            if resource_pool is not None:
                data['result'][0]['resourcePool'] = resource_pool.name
            else:
                data['result'][0]['resourcePool'] = ''

            if 'vm.type' in properties:
                data['result'][0]['vm.type'] = pool_type(data['result'][0]['resourcePool'])

        if 'triggeredAlarmState' in properties:
            triggeredAlarmState = data['result'][0].get('triggeredAlarmState')

            alarms = []
            alarm_count = 0
            alarms_filtered = []
            alarm_filtered_count = 0
            if triggeredAlarmState is not None:

                filteredAlarms = [
                    re.compile('^Virtual machine CPU usage$', re.IGNORECASE),
                    re.compile('^Virtual machine memory usage$', re.IGNORECASE),
                    re.compile('^VM Snapshot Size$', re.IGNORECASE),
                    re.compile('^Veyance - vMotion status - Basic$', re.IGNORECASE),
                    re.compile('^Veyance - vMotion status - Core$', re.IGNORECASE),
                    re.compile('^FCC - vMotion Status - Basic - CC cluster$', re.IGNORECASE),
                    re.compile('^FCC - vMotion Status - Core - CC cluster$', re.IGNORECASE),
                    re.compile('^NMT vMotion Alert$', re.IGNORECASE),
                ]

                for triggeredAlarm in triggeredAlarmState:
                    alarm_name = triggeredAlarm.alarm.info.name
                    alarm_desc = triggeredAlarm.alarm.info.description
                    entity = triggeredAlarm.entity.name
                    key = triggeredAlarm.key
                    filtered = False
                    for filteredAlarm in filteredAlarms:
                        if filteredAlarm.match(alarm_name):
                            filtered = True
                            alarm_filtered_count += 1
                            alarms_filtered.append(entity + ' - ' + key + ' - ' + alarm_name + ' - ' + alarm_desc)
                            break
                    if filtered:
                        continue
                    else:
                        alarm_count += 1
                        alarms.append(entity + ' - ' + key + ' - ' + alarm_name + ' - ' + alarm_desc)

                data['result'][0]['triggeredAlarmState'] = '\n'.join(alarms)
                data['result'][0]['triggeredAlarmFilteredState'] = '\n'.join(alarms_filtered)
            else:
                data['result'][0]['triggeredAlarmState'] = ''
                data['result'][0]['triggeredAlarmFilteredState'] = ''

            data['result'][0]['triggeredAlarmCount'] = alarm_count
            data['result'][0]['triggeredAlarmFilteredCount'] = alarm_filtered_count

        layout_snapshots_hash = {}
        if 'layoutEx' in properties:
            layout_hash = {}
            layout = data['result'][0].get('layoutEx')
            if layout is not None:

                files = []
                files_hash = {}
                for ffile in layout.file:
                    file_hash = {}
                    file_hash['accessible'] = ffile.accessible
                    file_hash['backingObjectId'] = ffile.backingObjectId
                    file_hash['key'] = ffile.key
                    file_hash['name'] = ffile.name
                    file_hash['size'] = ffile.size
                    file_hash['type'] = ffile.type
                    file_hash['uniqueSize'] = ffile.uniqueSize
                    files.append(file_hash)
                    files_hash[ffile.key] = file_hash
                layout_hash['file'] = files

                disks = []
                disks_hash = {}
                for disk in layout.disk:
                    disk_hash = {}
                    disk_hash['key'] = disk.key
                    chains = []
                    for chain in disk.chain:
                        chain_hash = {}
                        chain_hash['fileKey'] = chain.fileKey
                        chains.append(chain_hash)

                    disk_hash['snapshotDeltaSize'] = files_hash[disk.chain[-1].fileKey[-1]]['size']
                    disk_hash['snapshotDeltaUniqueSize'] = files_hash[disk.chain[-1].fileKey[-1]]['uniqueSize']

                    disk_hash['chain'] = chains

                    disks_hash[disk.key] = disk_hash
                layout_hash['disk'] = disks

                snapshots = []
                for snapshot in layout.snapshot:
                    snapshot_hash = {}
                    snapshot_hash['dataKey'] = snapshot.dataKey
                    snapshot_hash['memoryKey'] = snapshot.memoryKey
                    snapshot_hash['key'] = str(snapshot.key)

                    snapshot_disks = []
                    snapshot_delta_size = 0
                    snapshot_delta_unique_size = 0
                    for snapshot_disk in snapshot.disk:
                        snapshot_disk_hash = {}
                        snapshot_disk_hash['key'] = snapshot_disk.key

                        snapshot_chains = []
                        for snapshot_chain in snapshot_disk.chain:
                            snapshot_chain_hash = {}
                            snapshot_chain_hash['fileKey'] = snapshot_chain.fileKey
                        snapshot_disk_hash['chain'] = snapshot_chains

                        snapshot_disk_hash['snapshotDeltaSize'] = disks_hash[snapshot_disk.key]['snapshotDeltaSize']
                        snapshot_disk_hash['snapshotDeltaUniqueSize'] = disks_hash[snapshot_disk.key][
                            'snapshotDeltaUniqueSize']
                        snapshot_delta_size += snapshot_disk_hash['snapshotDeltaSize']
                        snapshot_delta_unique_size += snapshot_disk_hash['snapshotDeltaUniqueSize']

                        snapshot_disks.append(snapshot_disk_hash)
                    snapshot_hash['disk'] = snapshot_disks
                    snapshot_hash['snapshotDeltaSize'] = snapshot_delta_size
                    snapshot_hash['snapshotDeltaUniqueSize'] = snapshot_delta_unique_size

                    snapshots.append(snapshot_hash)
                    layout_snapshots_hash[snapshot_hash['key']] = snapshot_hash
                layout_hash['snapshot'] = snapshots

            data['result'][0]['layoutEx'] = layout_hash

        if 'snapshot' in properties:
            snapshot_hash = {}
            snapshot = data['result'][0].get('snapshot')
            if snapshot is not None:
                root_snapshots = []
                for root_snapshot in snapshot.rootSnapshotList:
                    root_snapshot_hash = {}
                    root_snapshot_hash['vm'] = root_snapshot.vm.name
                    root_snapshot_hash['name'] = root_snapshot.name
                    root_snapshot_hash['description'] = root_snapshot.description
                    root_snapshot_hash['id'] = root_snapshot.id
                    root_snapshot_hash['createTime'] = str(root_snapshot.createTime)
                    root_snapshot_hash['createTimeEpoch'] = (
                                root_snapshot.createTime - datetime.datetime(1970, 1, 1, 0, 0,
                                                                             tzinfo=root_snapshot.createTime.tzinfo)).total_seconds()
                    root_snapshot_hash['age'] = (datetime.datetime.now(
                        tz=root_snapshot.createTime.tzinfo) - root_snapshot.createTime).total_seconds()
                    root_snapshot_hash['state'] = root_snapshot.state
                    root_snapshot_hash['quiesced'] = root_snapshot.quiesced
                    root_snapshot_hash['snapshot'] = str(root_snapshot.snapshot)
                    root_snapshots.append(root_snapshot_hash)

                    layout_snapshot = layout_snapshots_hash.get(root_snapshot_hash['snapshot'])
                    if layout_snapshot is not None:
                        root_snapshot_hash['snapshotDeltaSize'] = layout_snapshot['snapshotDeltaSize']
                        root_snapshot_hash['snapshotDeltaUniqueSize'] = layout_snapshot['snapshotDeltaUniqueSize']
                    else:
                        root_snapshot_hash['snapshotDeltaSize'] = -1
                        root_snapshot_hash['snapshotDeltaUniqueSize'] = -1

                snapshot_hash['rootSnapshotList'] = root_snapshots
            data['result'][0]['snapshot'] = snapshot_hash

    return data


@task(name='vm.resource.pool.get', required=['name'])
def vm_resource_pool_get(agent, msg):
    """
    Get the ResourcePool objects attached to a specific VirtualMachine
    Example client message would be:
        {
            "method":     "vm.resource.pool.get",
            "hostname":   "vc01.example.org",
            "name":       "MyVM",
        }
    """
    logger.info(
        '[%s] Getting ResourcePool using VirtualMachine %s',
        agent.host,
        msg['name']
    )

    # Find the VirtualMachine by it's 'name' property
    # and get the ResourcePool object using it
    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=['name', 'config.instanceUuid', 'resourcePool'],
        obj_type=pyVmomi.vim.VirtualMachine,
        obj_property_name='config.instanceUuid',
        obj_property_value=msg['name']
    )

    if data['success'] != 0:
        return data

    # Get properties from the result
    props = data['result'][0]
    obj_host = [props['resourcePool']]

    # Get a list view of the ResourcePool from this VirtualMachine object
    # and collect their properties
    view_ref = agent.get_list_view(obj=obj_host)
    result = agent.collect_properties(
        view_ref=view_ref,
        obj_type=pyVmomi.vim.ResourcePool,
        path_set=['name']
    )

    view_ref.DestroyView()

    r = {
        'success': 0,
        'msg': 'Successfully discovered objects',
        'result': result,
    }

    return r


@task(name='vm.host.get', required=['name'])
def vm_host_get(agent, msg):
    """
    Get the vSphere host where a Virtual Machine is running on
    Override the base one which doesnt get the list of properties
    Example client message would be:
        {
            "method":     "vm.host.get",
            "hostname":   "vc01.example.org",
            "name":       "vm01.example.org",
        }

    Example client message requesting additional props would be:
        {
            "method":     "vm.host.get",
            "hostname":   "vc01.example.org",
            "name":       "vm01.example.org",
            "properties": [
                "name",
                "hardware.cpuInfo.hz"
            ]
        }

    Returns:
        The managed object properties in JSON format
    """
    logger.debug(
        '[%s] Getting host where %s VirtualMachine is running on',
        agent.host,
        msg['name']
    )

    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=['name', 'config.instanceUuid', 'runtime.host'],
        obj_type=pyVmomi.vim.VirtualMachine,
        obj_property_name='config.instanceUuid',
        obj_property_value=msg['name']
    )

    if data['success'] != 0:
        return data

    props = data['result'][0]
    vm_name, vm_host = props['name'], props['runtime.host']

    result = {}
    result['name'] = vm_name

    view_ref = agent.get_list_view(obj=[vm_host])
    result['host'] = agent.collect_properties(
        view_ref=view_ref,
        obj_type=pyVmomi.vim.HostSystem,
        path_set=['name']
    )
    result['host'] = result['host'][0]['name']

    view_ref.DestroyView()

    r = {
        'success': data['success'],
        'msg': data['msg'],
        'result': [result],
    }

    return r


@task(name='vm.hardware.discover', required=['name'])
def vm_hardware_discover(agent, msg):
    """
    Discover the hardware disks in a Virtual Machine
    Example client message would be:
        {
            "method":     "vm.hardware.disk.discover",
            "hostname":   "vc01.example.org",
            "name":       "vm01.example.org"
        }

    Returns:
        The managed object properties in JSON format
    """
    logger.debug(
        '[%s] Getting hardware.disk in VirtualMachine %s',
        agent.host,
        msg['name']
    )

    # Property names to be collected
    properties = ['name', 'config.instanceUuid', 'config.hardware.device']

    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=properties,
        obj_type=pyVmomi.vim.VirtualMachine,
        obj_property_name='config.instanceUuid',
        obj_property_value=msg['name']
    )

    if data['success'] != 0:
        return data

    props = data['result'][0]
    prop_devices = props['config.hardware.device']

    result = {}
    result_disk = []
    result_controller = []
    for prop_device in prop_devices:
        if isinstance(prop_device, pyVmomi.vim.vm.device.VirtualDisk):
            disk = {}
            for prop in ['unitNumber', 'capacityInKB', 'controllerKey']:
                disk[prop] = getattr(prop_device, prop, '(null)')
            disk_backing = getattr(prop_device, 'backing')
            for prop in ['fileName', 'uuid', 'datastore']:
                disk[prop] = getattr(disk_backing, prop, '(null)')
            disk_deviceInfo = getattr(prop_device, 'deviceInfo')
            for prop in ['label', 'summary']:
                disk[prop] = getattr(disk_deviceInfo, prop, '(null)')
            disk['datastore.path'] = disk['datastore'].host[0].mountInfo.path
            disk['datastore.summary.capacity'] = disk['datastore'].summary.capacity
            disk['datastore.summary.freeSpace'] = disk['datastore'].summary.freeSpace
            disk['datastore.summary.uncommitted'] = disk['datastore'].summary.uncommitted
            disk['datastore'] = disk['datastore'].name
            result_disk.append(disk)

        if (isinstance(prop_device, pyVmomi.vim.vm.device.VirtualLsiLogicController)
                or
                isinstance(prop_device, pyVmomi.vim.vm.device.VirtualLsiLogicSASController)
                or
                isinstance(prop_device, pyVmomi.vim.vm.device.ParaVirtualSCSIController)
                or
                isinstance(prop_device, pyVmomi.vim.vm.device.VirtualIDEController)
                or
                # isinstance(prop_device, pyVmomi.vim.vm.device.VirtualNVMEController)
                # or
                isinstance(prop_device, pyVmomi.vim.vm.device.VirtualSATAController)
                or
                isinstance(prop_device, pyVmomi.vim.vm.device.VirtualSCSIController)
                or
                isinstance(prop_device, pyVmomi.vim.vm.device.VirtualSIOController)
                or
                isinstance(prop_device, pyVmomi.vim.vm.device.VirtualAHCIController)
                or
                isinstance(prop_device, pyVmomi.vim.vm.device.VirtualBusLogicController)
        ):
            controller = {}
            for prop in ['key', 'controllerKey', 'busNumber', 'unitNumber', 'device']:
                controller[prop] = getattr(prop_device, prop, '(null)')
            result_controller.append(controller)

    result['virtualDisk'] = result_disk
    result['controller'] = result_controller

    r = {
        'success': data['success'],
        'msg': data['msg'],
        'result': result,
    }

    return r


@task(name='vm.net.discover', required=['name'])
def vm_net_discover(agent, msg):
    """
    Discover the NICs in a Virtual Machine
    Example client message would be:
        {
            "method":     "vm.guest.net.discover",
            "hostname":   "vc01.example.org",
            "name":       "vm01.example.org"
        }

    Returns:
        The managed object properties in JSON format
    """
    logger.debug(
        '[%s] Getting guest.net in VirtualMachine %s',
        agent.host,
        msg['name']
    )

    # Property names to be collected
    properties = ['name', 'config.instanceUuid', 'guest.net']

    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=properties,
        obj_type=pyVmomi.vim.VirtualMachine,
        obj_property_name='config.instanceUuid',
        obj_property_value=msg['name']
    )

    if data['success'] != 0:
        return data

    props = data['result'][0]
    prop_devices = props['guest.net']

    result = {}
    result_nic = []
    for prop_device in prop_devices:
        nic = {}

        for prop in ['connected', 'deviceConfigId', 'macAddress', 'ipAddress', 'network']:
            nic[prop] = getattr(prop_device, prop, 'UNKNOWN')

        result_nic.append(nic)

    result['nic'] = result_nic

    r = {
        'success': data['success'],
        'msg': data['msg'],
        'result': result,
    }

    return r


@task(name='vm.disk.discover', required=['name'])
def vm_disk_discover(agent, msg):
    """
    Discover all disks used by a vim.VirtualMachine managed object

    Note, that this request requires you to have
    VMware Tools installed in order get information about the
    guest disks.

    Example client message would be:

        {
            "method":   "vm.disk.discover",
            "hostname": "vc01.example.org",
            "name":     "vm01.example.org"
        }

    Example client message requesting
    additional properties to be collected:

        {
            "method":   "vm.disk.discover",
            "hostname": "vc01.example.org",
            "name":     "vm01.example.org",
            "properties": [
                "capacity",
                "diskPath",
                "freeSpace"
            ]
        }

    Returns:
        The discovered objects in JSON format

    """
    logger.debug(
        '[%s] Discovering guest disks for VirtualMachine %s',
        agent.host,
        msg['name']
    )

    # Find the VM and get the guest disks
    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=['name', 'config.instanceUuid', 'guest.disk'],
        obj_type=pyVmomi.vim.VirtualMachine,
        obj_property_name='config.instanceUuid',
        obj_property_value=msg['name'],
        include_mors=True
    )

    if data['success'] != 0:
        return data

    # Get the VM name and guest disk properties from the result
    props = data['result'][0]
    vm_name, vm_disks, vm_obj = props['name'], props['guest.disk'], props['obj']

    # Properties to be collected for the guest disks
    properties = ['diskPath']
    if 'properties' in msg and msg['properties']:
        properties.extend(msg['properties'])

    # Get the requested disk properties
    result = {}
    result['name'] = vm_name
    result['disk'] = [{prop: getattr(disk, prop, '(null)') for prop in properties} for disk in vm_disks]
    result['datastore'] = {'datastore.count': len(vm_obj.datastore)}

    r = {
        'success': 0,
        'msg': 'Successfully discovered objects',
        'result': [result],
    }

    return r


@task(name='vm.guestdisk.get', required=['name', 'username', 'password'])
def vm_guestdisk_get(agent, msg):
    """
    Get the guest disks in a vim.VirtualMachine managed object

    This method requires you to have VMware Tools installed and
    running in order to get the list of processes running in a
    guest system.

    Example client message would be:

        {
            "method":     "vm.guestdisk.get",
            "hostname":   "vc01.example.org",
            "name":       "vm01.example.org",
            "username":   "root",
            "password":   "p4ssw0rd"
        }

    Returns:
        The managed object properties in JSON format

    """

    # temporary no-op for rollout switing to instaneUUID instead of name
    # return {'success': 1, 'msg': 'temporary disable for rollout'}

    logger.debug(
        '[%s] Getting guestdisks for VirtualMachine %s',
        agent.host,
        msg['name']
    )

    # Get the VirtualMachine managed object
    data = _get_object_properties(
        agent=agent,
        properties=['name', 'config.instanceUuid', 'runtime.powerState', 'guest.toolsRunningStatus',
                    'guest.guestFamily'],
        obj_type=pyVmomi.vim.VirtualMachine,
        obj_property_name='config.instanceUuid',
        obj_property_value=msg['name'],
        include_mors=True
    )

    if data['success'] != 0:
        return data

    # Get the VM properties
    props = data['result'][0]
    vm_name, vm_powerstate, vm_tools_is_running, vm_obj, vm_guestfamily = props['name'], props['runtime.powerState'], \
                                                                          props['guest.toolsRunningStatus'], props[
                                                                              'obj'], props['guest.guestFamily']

    # Check if vm is powered on
    if vm_powerstate != 'poweredOn':
        return {
            'success': 1,
            'msg': '%s is not powered on' % vm_name
        }

    # Check if we have VMware Tools installed and running first as this request depends on it
    if vm_tools_is_running != 'guestToolsRunning':
        return {
            'success': 1,
            'msg': '%s is not running VMware Tools' % vm_name
        }

    # Prepare credentials used for
    # authentication in the guest system
    if not msg['username'] or not msg['password']:
        return {'success': 1, 'msg': 'Need username and password for authentication in guest system {}'.format(vm_name)}

    vm_creds = pyVmomi.vim.vm.guest.NamePasswordAuthentication(
        username=msg['username'],
        password=msg['password']
    )

    try:
        vm_processes = agent.si.content.guestOperationsManager.processManager.ListProcessesInGuest(
            vm=vm_obj,
            auth=vm_creds
        )
    except Exception as e:
        return {
            'success': 1,
            'msg': 'Cannot get guest processes: %s' % e
        }

    # Properties to be collected for the guest processes
    properties = ['cmdLine']
    if 'properties' in msg and msg['properties']:
        properties.extend(msg['properties'])

    # Get the requested process properties
    result = [{prop: getattr(process, prop, '(null)') for prop in properties} for process in vm_processes]

    r = {
        'success': 0,
        'msg': 'Successfully retrieved properties',
        'result': result,
    }

    return r


@task(name='vm.perf.metrics.get', required=['name', 'counter-name'])
def vm_perf_metrics_get(agent, msg):
    """
    Get performance metrics for a vim.VirtualMachine managed object

    Example client message would be:

        {
            "method":       "vm.perf.metrics.get",
            "hostname":     "vc01.example.org",
            "name":         "vm01.example.org",
            "counter-name": "cpu.usagemhz.megaHertz"
        }

    For historical performance statistics make sure to pass the
    performance interval as part of the message, e.g.:

        {
            "method":       "vm.perf.metrics.get",
            "hostname":     "vc01.example.org",
            "name":         "vm01.example.org",
            "counter-name": "cpu.usage.megaHertz",
            "perf-interval": "Past day"
        }

    Returns:
        The retrieved performance metrics

    """

    obj = agent.get_object_by_property(
        property_name='config.instanceUuid',
        property_value=msg['name'],
        obj_type=pyVmomi.vim.VirtualMachine
    )

    if not obj:
        return {'success': 1, 'msg': 'Cannot find object: {}'.format(msg['name'])}

    if obj.runtime.powerState != pyVmomi.vim.VirtualMachinePowerState.poweredOn:
        return {'success': 1, 'msg': 'VM is not powered on, cannot get performance metrics'}

    if obj.runtime.connectionState != pyVmomi.vim.VirtualMachineConnectionState.connected:
        return {'success': 1, 'msg': 'VM is not connected, cannot get performance metrics'}

    try:
        counter_name = msg.get('counter-name')
        max_sample = int(msg.get('max-sample')) if msg.get('max-sample') else 1
        interval_name = msg.get('perf-interval')
        instance = msg.get('instance') if msg.get('instance') else ''
    except (TypeError, ValueError):
        logger.warning('Invalid message, cannot retrieve performance metrics')
        return {
            'success': 1,
            'msg': 'Invalid message, cannot retrieve performance metrics'
        }

    ret = _entity_perf_metrics_get(
        agent=agent,
        entity=obj,
        counter_name=counter_name,
        max_sample=max_sample,
        instance=instance,
        interval_name=interval_name
    )

    if counter_name.startswith('virtualDisk.'):
        disk_info = vm_hardware_discover(agent, {'name': msg['name']})
        if disk_info['success'] != 0:
            return disk_info

        for metric in ret['result']:
            for controller in disk_info['result']['controller']:
                for disk in disk_info['result']['virtualDisk']:
                    if controller['key'] == disk['controllerKey'] and metric['instance'] == (
                            'scsi' + str(controller['busNumber']) + ':' + str(disk['unitNumber'])):
                        metric['uuid'] = disk['uuid']
                        metric['label'] = disk['label']
                        metric['summary'] = disk['summary']
                        metric['fileName'] = disk['fileName']
                        metric['capacityInKB'] = disk['capacityInKB']
                        metric['datastore'] = disk['datastore']
                        metric['datastore.path'] = disk['datastore.path']
                        metric['datastore.summary.capacity'] = disk['datastore.summary.capacity']
                        metric['datastore.summary.freeSpace'] = disk['datastore.summary.freeSpace']
                        metric['datastore.summary.uncommitted'] = disk['datastore.summary.uncommitted']
    elif counter_name.startswith('net.'):
        # filter out vmnic* instances which are the underlying hypervisors nics and this vm's usage of them
        device_info = vm_net_discover(agent, {'name': msg['name']})
        if device_info['success'] != 0:
            return device_info

        device_info_by_config_id = {}
        for dev_info in device_info['result']['nic']:
            device_info_by_config_id[str(dev_info['deviceConfigId'])] = dev_info

        result_new = []
        for metric in ret['result']:
            if not metric['instance'].startswith('vmnic'):
                result_new.append(metric)
                dev = device_info_by_config_id.get(metric['instance'])
                if dev is None:
                    dev = {'macAddress': 'UNKNOWN', 'ipAddress': ['UNKNOWN'], 'connected': 'UNKNOWN',
                           'deviceConfigId': 'UNKNOWN', 'network': 'UNKNOWN'}
                metric['macAddress'] = dev['macAddress']
                metric['network'] = dev['network']
                metric['connected'] = dev['connected']
                metric['ipAddress'] = dev['ipAddress']

        ret['result'] = result_new

    # get resource pool...
    view_ref = agent.get_list_view(obj=[obj])
    try:
        data = agent.collect_properties(
            view_ref=view_ref,
            obj_type=pyVmomi.vim.VirtualMachine,
            path_set=['config.instanceUuid', 'resourcePool'],
            include_mors=False
        )

        resource_pool = 'UNKNOWN'
        for d in data:
            resource_pool = d.get('resourcePool')
            if resource_pool is not None:
                resource_pool = resource_pool.name
                break

        for metric in ret['result']:
            metric['resourcePool'] = resource_pool
    except Exception as e:
        return {'success': 1, 'msg': 'Cannot collect properties (resourcepool): {}'.format(e.message)}

    view_ref.DestroyView()

    return ret


# @task(name='host.get', required=['name', 'properties'])
# def host_get(agent, msg):
#    logger.info('properties: ' + str(msg['properties']))
#
#    return vpoller.vsphere.tasks.host_get(agent,msg)

@task(name='host.get', required=['name', 'properties'])
def host_get(agent, msg):
    """
    Get properties of a single vim.HostSystem managed object

    Example client message would be:

    {
        "method":     "host.get",
        "hostname":   "vc01.example.org",
        "name":       "esxi01.example.org",
        "properties": [
            "name",
            "runtime.powerState"
        ]


    Returns:
        The managed object properties in JSON format

    """

    # Property names to be collected
    properties = ['name']
    if 'properties' in msg and msg['properties']:
        properties.extend(msg['properties'])

    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=properties,
        obj_type=pyVmomi.vim.HostSystem,
        obj_property_name='name',
        obj_property_value=msg['name']
    )

    if data.get('result') is not None:
        if 'vm' in properties:
            vms = []
            vms_data = data['result'][0].get('vm')
            if vms_data is None:
                vms_data = []
            for vm in vms_data:
                vms.append(vm.name)

            data['result'][0]['vm'] = vms

        if 'parent' in properties:
            parent = data['result'][0].get('parent')
            if parent is not None:
                data['result'][0]['parent'] = parent.name
            else:
                data['result'][0]['parent'] = ''

        if 'triggeredAlarmState' in properties:
            triggeredAlarmState = data['result'][0].get('triggeredAlarmState')

            alarms = []
            alarm_count = 0
            alarms_filtered = []
            alarm_filtered_count = 0
            if triggeredAlarmState is not None:

                filteredAlarms = [
                    re.compile('^Host CPU usage$', re.IGNORECASE),
                    re.compile('^Host memory usage$', re.IGNORECASE),
                ]

                for triggeredAlarm in triggeredAlarmState:
                    alarm_name = triggeredAlarm.alarm.info.name
                    alarm_desc = triggeredAlarm.alarm.info.description
                    entity = triggeredAlarm.entity.name
                    key = triggeredAlarm.key
                    filtered = False
                    for filteredAlarm in filteredAlarms:
                        if filteredAlarm.match(alarm_name):
                            filtered = True
                            alarm_filtered_count += 1
                            alarms_filtered.append(entity + ' - ' + key + ' - ' + alarm_name + ' - ' + alarm_desc)
                            break
                    if filtered:
                        continue
                    else:
                        alarm_count += 1
                        alarms.append(entity + ' - ' + key + ' - ' + alarm_name + ' - ' + alarm_desc)

                data['result'][0]['triggeredAlarmState'] = '\n'.join(alarms)
                data['result'][0]['triggeredAlarmFilteredState'] = '\n'.join(alarms_filtered)
            else:
                data['result'][0]['triggeredAlarmState'] = ''
                data['result'][0]['triggeredAlarmFilteredState'] = ''

            data['result'][0]['triggeredAlarmCount'] = alarm_count
            data['result'][0]['triggeredAlarmFilteredCount'] = alarm_filtered_count

    return data


@task(name='host.log.info', required=['name', 'properties'])
def host_log_info(agent, msg):
    """
    Get log info of a single vim.HostSystem managed object

    Example client message would be:

    {
        "method":     "host.log.info",
        "hostname":   "vc01.example.org",
        "name":       "esxi01.example.org",
        "properties": [
            "name",
            "runtime.powerState"
        ]
    }

    Returns:
        The logfile info in JSON

    """

    obj = agent.get_object_by_property(
        property_name='name',
        property_value=msg['name'],
        obj_type=pyVmomi.vim.HostSystem
    )

    diagmgr = agent.si.content.diagnosticManager
    log = diagmgr.QueryDescriptions(host=obj)
    result = []
    for l in log:
        result.append({'key': l.key, 'fileName': l.fileName})

    r = {
        'success': 0,
        'msg': 'Successfully discovered objects',
        'result': result,
    }

    return r


@task(name='host.log.get', required=['name', 'properties'])
def host_log_get(agent, msg):
    """
    Get log of a single vim.HostSystem managed object

    Example client message would be:

    {
        "method":     "host.log.get",
        "hostname":   "vc01.example.org",
        "name":       "esxi01.example.org",
        "properties": [
            "name",
            "runtime.powerState"
        ]
    }

    Returns:
        The logfile content in JSON

    """

    obj = agent.get_object_by_property(
        property_name='name',
        property_value=msg['name'],
        obj_type=pyVmomi.vim.HostSystem
    )

    diagmgr = agent.si.content.diagnosticManager
    log = diagmgr.QueryDescriptions(host=obj)
    result = []
    for prop in msg['properties']:
        log = diagmgr.BrowseDiagnosticLog(host=obj, key=prop, start=999999999)
        logging.info('log:' + str(log))
        lines = log.lineEnd

        lineText = []
        i = 1
        while i < lines:
            log_segment = diagmgr.BrowseDiagnosticLog(host=obj, key=prop, start=i, lines=i + 999)
            lineText.extend(log_segment.lineText)
            i += 999
        result.append({prop: {'lineStart': 1, 'lineEnd': lines, 'lineText': lineText}})

    r = {
        'success': 0,
        'msg': 'Successfully discovered objects',
        'result': result,
    }

    return r


@task(name='host.perf.metrics.get', required=['name', 'counter-name'])
def host_perf_metrics_get(agent, msg):
    """
    Get performance metrics for a vim.HostSystem managed object

    Example client message would be:

    {
        "method":       "host.perf.metrics.get",
        "hostname":     "vc01.example.org",
        "name":         "esxi01.example.org",
        "counter-name": "net.usage.kiloBytesPerSecond",
        "instance":     "vmnic0",
        "max_sample": 1
    }

    Returns:
        The retrieved performance metrics

    """
    obj = agent.get_object_by_property(
        property_name='name',
        property_value=msg['name'],
        obj_type=pyVmomi.vim.HostSystem
    )

    if not obj:
        return {'success': 1, 'msg': 'Cannot find object: {}'.format(msg['name'])}

    if obj.runtime.powerState != pyVmomi.vim.HostSystemPowerState.poweredOn:
        return {'success': 1, 'msg': 'Host is not powered on, cannot get performance metrics'}

    if obj.runtime.connectionState != pyVmomi.vim.HostSystemConnectionState.connected:
        return {'success': 1, 'msg': 'Host is not connected, cannot get performance metrics'}

    try:
        counter_name = msg.get('counter-name')
        max_sample = int(msg.get('max-sample')) if msg.get('max-sample') else 1
        interval_name = msg.get('perf-interval')
        instance = msg.get('instance') if msg.get('instance') else ''
    except (TypeError, ValueError):
        logger.warning('Invalid message, cannot retrieve performance metrics')
        return {
            'success': 1,
            'msg': 'Invalid message, cannot retrieve performance metrics'
        }

    return _entity_perf_metrics_get(
        agent=agent,
        entity=obj,
        counter_name=counter_name,
        max_sample=max_sample,
        instance=instance,
        interval_name=interval_name
    )


@task(name='vm.datacenter.get', required=['name'])
def vm_datacenter_get(agent, msg):
    """
    Get the Datacenter object attached to a specific VirtualMachine
    Example client message would be:
        {
            "method":     "vm.datacenter.get",
            "hostname":   "vc01.example.org",
            "name":       "MyVM",
        }
    """
    logger.info(
        '[%s] Getting Datacenter using VirtualMachine %s',
        agent.host,
        msg['name']
    )

    # Find the VirtualMachine by it's 'name' property
    # and get the Datacenter object using it
    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=['name', 'config.instanceUuid', 'parent'],
        obj_type=pyVmomi.vim.VirtualMachine,
        obj_property_name='config.instanceUuid',
        obj_property_value=msg['name']
    )

    if data['success'] != 0:
        return data

    # Get properties from the result
    props = data['result'][0]
    obj_datacenter = props['parent']

    # walk the parent heirarchy until the datacenter parent is found
    obj_datacenter = [_parent_recurse(obj_datacenter, 'pyVmomi.VmomiSupport.vim.Datacenter')]

    # Get a list view of the Datacenter from this VirtualMachine object
    # and collect their properties
    view_ref = agent.get_list_view(obj=obj_datacenter)
    result = agent.collect_properties(
        view_ref=view_ref,
        obj_type=pyVmomi.vim.Datacenter,
        path_set=['name']
    )

    view_ref.DestroyView()

    r = {
        'success': 0,
        'msg': 'Successfully discovered objects',
        'result': result,
    }

    return r


@task(name='host.datacenter.get', required=['name'])
def host_datacenter_get(agent, msg):
    """
    Get the Datacenter object attached to a specific HostSystem
    Example client message would be:
        {
            "method":     "host.datacenter.get",
            "hostname":   "vc01.example.org",
            "name":       "MyHostSystem",
        }
    """
    logger.info(
        '[%s] Getting Datacenter using HostSystem %s',
        agent.host,
        msg['name']
    )

    # Find the HostSystem by it's 'name' property
    # and get the Datacenter object using it
    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=['name', 'parent'],
        obj_type=pyVmomi.vim.HostSystem,
        obj_property_name='name',
        obj_property_value=msg['name']
    )

    if data['success'] != 0:
        return data

    # Get properties from the result
    props = data['result'][0]
    obj_datacenter = props['parent']

    # walk the parent heirarchy until the datacenter parent is found
    obj_datacenter = [_parent_recurse(obj_datacenter, 'pyVmomi.VmomiSupport.vim.Datacenter')]

    # Get a list view of the Datacenter from this VirtualMachine object
    # and collect their properties
    view_ref = agent.get_list_view(obj=obj_datacenter)
    result = agent.collect_properties(
        view_ref=view_ref,
        obj_type=pyVmomi.vim.Datacenter,
        path_set=['name']
    )

    view_ref.DestroyView()

    r = {
        'success': 0,
        'msg': 'Successfully discovered objects',
        'result': result,
    }

    return r


@task(name='host.multipathinfo.get', required=['name'])
def host_multipathinfo_get(agent, msg):
    """
    Get the HostMultipathStateInfoPath objects attached to a specific HostSystem
    Example client message would be:
        {
            "method":     "host.multipath.get",
            "hostname":   "vc01.example.org",
            "name":       "MyHostSystem",
        }
    """
    logger.info(
        '[%s] Getting HostMultipath using HostSystem %s',
        agent.host,
        msg['name']
    )

    # Find the HostSystem by it's 'name' property
    # and get the HostConfigInfo object using it
    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=['name', 'config.storageDevice.multipathInfo.lun'],
        obj_type=pyVmomi.vim.HostSystem,
        obj_property_name='name',
        obj_property_value=msg['name']
    )

    if data['success'] != 0:
        return data

    # Get properties from the result
    props = data['result'][0]

    obj_multipathinfo = props['config.storageDevice.multipathInfo.lun']

    result = [{prop: getattr(lun, prop, '(null)') for prop in ['id', 'path', 'lun', 'policy', 'storageArrayTypePolicy']}
              for lun in obj_multipathinfo]
    result2 = []
    for r in result:
        lun_paths = []
        is_working_count = 0
        active_count = 0
        standby_count = 0
        disabled_count = 0
        dead_count = 0
        unknown_count = 0
        for path in r['path']:
            p = {prop: getattr(path, prop, '(null)') for prop in ['key', 'name', 'state', 'isWorkingPath', 'adapter']}
            if p['isWorkingPath'] == True:
                is_working_count += 1
            if p['state'] == 'active':
                active_count += 1
            elif p['state'] == 'standby':
                standby_count += 1
            elif p['state'] == 'disabled':
                disabled_count += 1
            elif p['state'] == 'dead':
                dead_count += 1
            elif p['state'] == 'unknown':
                unknown_count += 1
            transport = getattr(path, 'transport', '(null)')
            p['transportPortWorldWideName'] = getattr(transport, 'portWorldWideName', '(null)')
            p['transportNodeWorldWideName'] = getattr(transport, 'nodeWorldWideName', '(null)')
            p['lun'] = r['lun']
            p['lunid'] = r['id']
            p['policy'] = r['policy'].policy
            p['storageArrayTypePolicy'] = r['storageArrayTypePolicy'].policy
            lun_paths.append(p)
        for lun_path in lun_paths:
            lun_path['pathCount'] = len(lun_paths)
            lun_path['pathCountIsWorking'] = is_working_count
            lun_path['pathCountStateActive'] = active_count
            lun_path['pathCountStateStandby'] = standby_count
            lun_path['pathCountStateDisabled'] = disabled_count
            lun_path['pathCountStateDead'] = dead_count
            lun_path['pathCountStateUnknown'] = unknown_count
            result2.append(lun_path)

    r = {
        'success': 0,
        'msg': 'Successfully discovered objects',
        'result': result2,
    }

    return r


@task(name='host.multipathinfo.summary', required=['name'])
def host_multipathinfo_summary(agent, msg):
    """
    Get the HostMultipathStateInfoPath objects attached to a specific HostSystem and generate a summary
    Example client message would be:
        {
            "method":     "host.multipath.get",
            "hostname":   "vc01.example.org",
            "name":       "MyHostSystem",
        }
    """
    logger.info(
        '[%s] Getting HostMultipath Summary using HostSystem %s',
        agent.host,
        msg['name']
    )

    # Find the HostSystem by it's 'name' property
    # and get the HostConfigInfo object using it
    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=['name', 'config.storageDevice.scsiLun', 'config.fileSystemVolume.mountInfo', 'datastore',
                    'summary.host', 'config.storageDevice.plugStoreTopology.device',
                    'config.storageDevice.plugStoreTopology.path', 'config.storageDevice.plugStoreTopology.adapter',
                    'config.multipathState.path'],
        obj_type=pyVmomi.vim.HostSystem,
        obj_property_name='name',
        obj_property_value=msg['name']
    )

    if data['success'] != 0:
        return data

    # Get properties from the result
    props = data['result'][0]

    # lookup cache
    cache_file = '/var/log/vpoller'
    for path_part in ['vpoller_trapper', msg['method'], msg['hostname'], msg['name']]:
        cache_file = cache_file + '/' + path_part
        if not os.path.exists(cache_file):
            os.makedirs(cache_file)
    cache_file = cache_file + '/lun_disk_datastore_mapping.json'

    lun_disk_datastore_mapping = None
    if os.path.exists(cache_file):
        with open(cache_file) as lun_disk_datastore_mapping_file:
            try:
                lun_disk_datastore_mapping = json.load(lun_disk_datastore_mapping_file)
            except ValueError as e:
                lun_disk_datastore_mapping = None  # force it to be over-written
                logger.info('Problem reading lun_disk_datastore_mapping file: ' + cache_file)

    current_time = int(time.time())
    disk_without_volume = None
    volume_without_datastore = None
    if lun_disk_datastore_mapping is None or lun_disk_datastore_mapping['expires'] < current_time:
        disk_without_volume = {}
        volume_without_datastore = {}

        # build volpath:datastore dict
        datastore_by_volpath = {}
        obj_host = props['summary.host']
        obj_datastores = props['datastore']
        for obj_datastore in obj_datastores:
            for mountInfo in obj_datastore.host:
                if mountInfo.key == obj_host:
                    datastore_by_volpath[mountInfo.mountInfo.path] = obj_datastore.name
                    break

        # build diskname:volpath dict
        volpath_by_diskname = {}
        vols = props['config.fileSystemVolume.mountInfo']
        for vol in vols:
            extents = getattr(getattr(vol, 'volume'), 'extent', '(null)')
            if extents != '(null)':
                for extent in extents:
                    volpath_by_diskname[getattr(extent, 'diskName', '(null)')] = getattr(getattr(vol, 'mountInfo'),
                                                                                         'path', '(null)')

        # build lun:diskname dict
        diskname_by_lun = {}
        luns = props['config.storageDevice.scsiLun']
        for lun in luns:
            lun_key = getattr(lun, 'key', '(null)')
            diskname_by_lun[lun_key] = {'diskName': getattr(lun, 'canonicalName', '(null)')}
            diskname_by_lun[lun_key]['volPath'] = volpath_by_diskname.get(diskname_by_lun[lun_key]['diskName'])
            if diskname_by_lun[lun_key]['volPath'] is None:
                disk_without_volume[lun_key] = True

                diskname_by_lun[lun_key]['volPath'] = 'No Volume Associated (mapping cache refresh every hour)'
                diskname_by_lun[lun_key][
                    'datastore'] = 'No Volume/Datastore Associated (Mapping cache refresh every hour)'
            else:
                disk_without_volume[lun_key] = False

                diskname_by_lun[lun_key]['datastore'] = datastore_by_volpath.get(diskname_by_lun[lun_key]['volPath'])
                if diskname_by_lun[lun_key]['datastore'] is None:
                    volume_without_datastore[lun_key] = True
                    diskname_by_lun[lun_key]['datastore'] = 'No Datastore Associated (mapping cache refresh every hour)'
                else:
                    volume_without_datastore[lun_key] = False

        # write mapping to a file
        with open(cache_file, 'w') as lun_disk_datastore_mapping_file:
            cache = {'expires': (current_time + random.randint(1800, 3600)), 'diskname_by_lun': diskname_by_lun}
            json.dump(cache, lun_disk_datastore_mapping_file)

    else:
        diskname_by_lun = lun_disk_datastore_mapping['diskname_by_lun']

    # check the paths...
    plugstore_paths = props['config.storageDevice.plugStoreTopology.path']
    path_by_key = {}
    for plugstore_path in plugstore_paths:
        path_by_key[getattr(plugstore_path, 'key')] = {prop: getattr(plugstore_path, prop) for prop in
                                                       ['key', 'name', 'adapter']}

    pathstates = props['config.multipathState.path']
    pathstate_by_name = {}
    for pathstate in pathstates:
        pathstate_by_name[getattr(pathstate, 'name')] = {prop: getattr(pathstate, prop) for prop in
                                                         ['name', 'pathState']}

    adapters = props['config.storageDevice.plugStoreTopology.adapter']
    adapter_by_key = {}
    for adapter in adapters:
        adapter_by_key[getattr(adapter, 'key')] = {prop: getattr(adapter, prop) for prop in ['adapter']}

    plugstore_devices = props['config.storageDevice.plugStoreTopology.device']

    total_count = 0
    active_count = 0
    standby_count = 0
    standby_list = []
    disabled_count = 0
    disabled_list = []
    dead_count = 0
    dead_list = []
    unknown_count = 0
    unknown_list = []
    disk_without_volume_count = 0
    disk_without_volume_list = []
    volume_without_datastore_count = 0
    volume_without_datastore_list = []

    unbalanced_pathing_count = 0
    unbalanced_pathing_list = []
    for plugstore_device in plugstore_devices:
        lun = getattr(plugstore_device, 'lun')

        path_log = []
        path_log.append('Datastore: ' + diskname_by_lun[lun]['datastore'])
        path_log.append('VolumePath: ' + diskname_by_lun[lun]['volPath'])
        path_log.append('DiskName: ' + diskname_by_lun[lun]['diskName'])
        path_log.append('LUN: ' + lun)

        path_details = {'by_hba': {}, 'active_path_count': 0, 'standby_path_count': 0, 'disabled_path_count': 0,
                        'dead_path_count': 0, 'unknown_path_count': 0, 'not_working_path_count': 0,
                        'working_path_count': 0, 'unbalanced_path_count': 0, 'unbalanced_reason': [],
                        'adapter_count': 0}

        for path in getattr(plugstore_device, 'path'):

            plugstore_path = path_by_key[path]
            state = pathstate_by_name[plugstore_path['name']]

            p = {'key': plugstore_path['key'], 'name': plugstore_path['name'],
                 'adapter': adapter_by_key[plugstore_path['adapter']]['adapter'], 'state': state['pathState']}

            total_count += 1

            path_string = ('(' + p['state'] + ') ').rjust(12) + p['name']
            if path_details['by_hba'].get(p['adapter']) is None:
                path_details['by_hba'][p['adapter']] = {'lun': lun, 'adapterType': p['adapter'], 'path_count': 1,
                                                        'paths': [path_string]}
                if p['adapter'].startswith('key-vim.host.FibreChannelHba'):
                    path_details['adapter_count'] += 1
            else:
                path_details['by_hba'][p['adapter']]['path_count'] += 1
                path_details['by_hba'][p['adapter']]['paths'].append(path_string)

            if p['state'] == 'active':
                active_count += 1
                path_details['active_path_count'] += 1
            elif p['state'] == 'standby':
                standby_count += 1
                path_details['standby_path_count'] += 1
            elif p['state'] == 'disabled':
                disabled_count += 1
                path_details['disabled_path_count'] += 1
            elif p['state'] == 'dead':
                dead_count += 1
                path_details['dead_path_count'] += 1
            elif p['state'] == 'unknown':
                unknown_count += 1
                path_details['unknown_path_count'] += 1

        running_path_count = -1
        for adapter, path_hash in path_details['by_hba'].iteritems():
            path_log.append('\tHBA: ' + adapter)
            for path in path_hash['paths']:
                path_log.append('\t\t' + path)

            if adapter.startswith('key-vim.host.FibreChannelHba'):
                # if path_hash['path_count'] > 2:
                #    path_details['unbalanced_path_count'] += 1
                #    path_details['unbalanced_reason'].append('Over2PathsPerHBA_'+adapter)

                if path_hash['path_count'] % 2 != 0:
                    path_details['unbalanced_path_count'] += 1
                    path_details['unbalanced_reason'].append('OddNumberOfPathsOn_' + adapter)
                else:
                    if running_path_count < 0:
                        running_path_count = path_hash['path_count']
                    else:
                        if running_path_count != path_hash['path_count']:
                            path_details['unbalanced_path_count'] += 1
                            path_details['unbalanced_reason'].append('UnbalancedPathsCountAcrossAllHBAs')
        if path_details['adapter_count'] % 2 != 0:
            path_details['unbalanced_path_count'] += 1
            path_details['unbalanced_reason'].append('OddNumberOfHBAs_' + str(path_details['adapter_count']))

        path_log.append('')

        if path_details['standby_path_count'] > 0:
            standby_list.extend(path_log)
        if path_details['disabled_path_count'] > 0:
            disabled_list.extend(path_log)
        if path_details['dead_path_count'] > 0:
            dead_list.extend(path_log)
        if path_details['unknown_path_count'] > 0:
            unknown_list.extend(path_log)
        if path_details['unbalanced_path_count'] > 0 or path_details['adapter_count'] % 2 != 0:
            unbalanced_pathing_count += 1
            reasons = ':::'.join(path_details['unbalanced_reason'])
            unbalanced_pathing_list.append('Problems: ' + reasons)
            unbalanced_pathing_list.extend(path_log)

        if disk_without_volume is not None and disk_without_volume[lun]:
            disk_without_volume_count += 1
            disk_without_volume_list.extend(path_log)

        if volume_without_datastore is not None and disk_without_volume[lun] == False and volume_without_datastore[lun]:
            volume_without_datastore_count += 1
            volume_without_datastore_list.extend(path_log)

    result = [{
        'storagePath.summary.totalPathCount': total_count,
        'storagePath.summary.activePathCount': active_count,
        'storagePath.summary.standbyPathCount': standby_count,
        'storagePath.summary.standbyPaths': '\n'.join(standby_list),
        'storagePath.summary.disabledPathCount': disabled_count,
        'storagePath.summary.disabledPaths': '\n'.join(disabled_list),
        'storagePath.summary.deadPathCount': dead_count,
        'storagePath.summary.deadPaths': '\n'.join(dead_list),
        'storagePath.summary.unknownPathCount': unknown_count,
        'storagePath.summary.unknownPaths': '\n'.join(unknown_list),
        'storagePath.summary.unbalancedPathCount': unbalanced_pathing_count,
        'storagePath.summary.unbalancedPaths': '\n'.join(unbalanced_pathing_list)
    }]

    if disk_without_volume is not None:
        result[0]['storage_orphans_disks_without_volume'] = '\n'.join(disk_without_volume_list)
        result[0]['storage_orphans_disks_without_volume_count'] = disk_without_volume_count
        result[0]['storage_orphans_volumes_without_datastore'] = '\n'.join(volume_without_datastore_list)
        result[0]['storage_orphans_volumes_without_datastore_count'] = volume_without_datastore_count

    r = {
        'success': 0,
        'msg': 'Successfully discovered objects',
        'result': result,
    }

    return r


@task(name='host.cpupkg.get', required=['name'])
def host_cpupkg_get(agent, msg):
    """
    Get all HostCpuPackage objects attached to a specific HostSystem
    Example client message would be:
        {
            "method":     "host.cpupkg.get",
            "hostname":   "vc01.example.org",
            "name":       "MyHost",
        }
    """
    logger.info(
        '[%s] Getting HostCpuPackage list using HostSystem %s',
        agent.host,
        msg['name']
    )

    # Find the HostSystem by it's 'name' property
    # and get the HostCpuPackage objects using it
    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=['name', 'hardware.cpuPkg'],
        obj_type=pyVmomi.vim.HostSystem,
        obj_property_name='name',
        obj_property_value=msg['name']
    )

    if data['success'] != 0:
        return data

    # Get properties from the result
    props = data['result'][0]
    obj_cpupkg = props['hardware.cpuPkg']

    result = []
    for cpupkg in obj_cpupkg:
        result.append(
            {'description': cpupkg.description, 'vendor': cpupkg.vendor, 'busHz': cpupkg.busHz, 'hz': cpupkg.hz,
             'index': cpupkg.index, 'threadId': cpupkg.threadId})

    r = {
        'success': 0,
        'msg': 'Successfully discovered objects',
        'result': result,
    }

    return r


def cluster_zone(cluster_name):
    if re.match('^........C', cluster_name) or re.match('^........H', cluster_name) or re.match('^........X',
                                                                                                cluster_name) or re.match(
            '^........Y', cluster_name):
        cluster_zone = 'IZ'
    elif re.match('^........D', cluster_name):
        cluster_zone = 'DZ'
    elif re.match('^........M', cluster_name):
        cluster_zone = 'MZ'
    else:
        cluster_zone = 'Unknown'

    return cluster_zone


@task(name='cluster.get', required=['name', 'properties'])
def cluster_get(agent, msg):
    """
    Get properties of a vim.ClusterComputeResource managed object

    Example client message would be:

    {
        "method":     "cluster.get",
        "hostname":   "vc01.example.org",
            "name":       "MyCluster",
            "properties": [
            "name",
            "overallStatus"
        ]
    }

    Returns:
        The managed object properties in JSON format

    """

    # Property names to be collected
    properties = ['name']
    if 'properties' in msg and msg['properties']:
        properties.extend(msg['properties'])

    host_vm = False
    if 'host.vm' in properties:
        properties.remove('host.vm')
        host_vm = True

    if 'cluster.zone' in properties:
        properties.remove('cluster.zone')

    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=properties,
        obj_type=pyVmomi.vim.ClusterComputeResource,
        obj_property_name='name',
        obj_property_value=msg['name']
    )

    if data.get('result') is not None:
        if 'cluster.zone' in msg['properties']:
            data['result'][0]['cluster.zone'] = cluster_zone(msg['name'])

        if 'host' in properties:
            hosts = []
            vms = []
            hosts_data = data['result'][0].get('host')
            if hosts_data is None:
                hosts_data = []
            for host in hosts_data:
                hosts.append(host.name)

                if host_vm:
                    # for vm in host.vm:
                    #    vms.append(vm.name)

                    # this is faster by far than just walking the path....
                    data_host = vpoller.vsphere.tasks._get_object_properties(
                        agent=agent,
                        properties=['name', 'vm'],
                        obj_type=pyVmomi.vim.HostSystem,
                        obj_property_name='name',
                        obj_property_value=host.name
                    )
                    if data_host.get('result') is not None:
                        for vm in data_host['result'][0]['vm']:
                            vms.append(vm.name)

            data['result'][0]['host'] = hosts
            if host_vm:
                data['result'][0]['host.vm'] = vms

        if 'triggeredAlarmState' in properties:
            triggeredAlarmState = data['result'][0].get('triggeredAlarmState')

            alarms = []
            alarm_count = 0
            alarms_filtered = []
            alarm_filtered_count = 0
            if triggeredAlarmState is not None:

                filteredAlarms = [
                    re.compile('^Host CPU usage$', re.IGNORECASE),
                    re.compile('^Host memory usage$', re.IGNORECASE),
                    re.compile('^Virtual machine CPU usage$', re.IGNORECASE),
                    re.compile('^Virtual machine memory usage$', re.IGNORECASE),
                    re.compile('^Deploying a Virtual Machine$', re.IGNORECASE),
                ]

                for triggeredAlarm in triggeredAlarmState:
                    alarm_name = triggeredAlarm.alarm.info.name
                    alarm_desc = triggeredAlarm.alarm.info.description
                    entity = triggeredAlarm.entity.name
                    key = triggeredAlarm.key
                    filtered = False
                    for filteredAlarm in filteredAlarms:
                        if filteredAlarm.match(alarm_name):
                            filtered = True
                            alarm_filtered_count += 1
                            alarms_filtered.append(entity + ' - ' + key + ' - ' + alarm_name + ' - ' + alarm_desc)
                            break
                    if filtered:
                        continue
                    else:
                        alarm_count += 1
                        alarms.append(entity + ' - ' + key + ' - ' + alarm_name + ' - ' + alarm_desc)

                data['result'][0]['triggeredAlarmState'] = '\n'.join(alarms)
                data['result'][0]['triggeredAlarmFilteredState'] = '\n'.join(alarms_filtered)
            else:
                data['result'][0]['triggeredAlarmState'] = ''
                data['result'][0]['triggeredAlarmFilteredState'] = ''

            data['result'][0]['triggeredAlarmCount'] = alarm_count
            data['result'][0]['triggeredAlarmFilteredCount'] = alarm_filtered_count

    return data


@task(name='cluster.host.get', required=['name'])
def cluster_host_get(agent, msg):
    """
    Get all HostSystem objects attached to a specific Cluster
    Example client message would be:
        {
            "method":     "cluster.host.get",
            "hostname":   "vc01.example.org",
            "name":       "MyCluster",
        }
    """
    logger.info(
        '[%s] Getting HostSystem list using Cluster %s',
        agent.host,
        msg['name']
    )

    obj = agent.get_object_by_property(
        property_name='name',
        property_value=msg['name'],
        obj_type=pyVmomi.vim.ClusterComputeResource
    )

    if not obj:
        return {'success': 1, 'msg': 'Cannot find object: {}'.format(msg['name'])}

    hosts = []
    vms = []
    for host in obj.host:
        hosts.append(host.name)
        for vm in host.vm:
            vms.append(vm.name)

    r = {
        'success': 0,
        'msg': 'Successfully discovered objects',
        'result': result,
    }

    return r


@task(name='cluster.resource.pool.get', required=['name'])
def cluster_resource_pool_get(agent, msg):
    """
    Get the ResourcePool objects attached to a specific Cluster
    Example client message would be:
        {
            "method":     "cluster.resource.pool.get",
            "hostname":   "vc01.example.org",
            "name":       "MyCluster",
        }
    """
    logger.info(
        '[%s] Getting ResourcePool using Cluster %s',
        agent.host,
        msg['name']
    )

    # Find the Cluster by it's 'name' property
    # and get the ResourcePool object using it
    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=['name', 'resourcePool'],
        obj_type=pyVmomi.vim.ClusterComputeResource,
        obj_property_name='name',
        obj_property_value=msg['name']
    )

    if data['success'] != 0:
        return data

    # Get properties from the result
    props = data['result'][0]
    obj_host = [props['resourcePool']]

    # Get a list view of the ResourcePool from this VirtualMachine object
    # and collect their properties
    view_ref = agent.get_list_view(obj=obj_host)
    result = agent.collect_properties(
        view_ref=view_ref,
        obj_type=pyVmomi.vim.ResourcePool,
        path_set=['name']
    )

    view_ref.DestroyView()

    r = {
        'success': 0,
        'msg': 'Successfully discovered objects',
        'result': result,
    }

    return r


@task(name='cluster.datacenter.get', required=['name'])
def cluster_datacenter_get(agent, msg):
    """
    Get the Datacenter object attached to a specific Cluster
    Example client message would be:
        {
            "method":     "host.datacenter.get",
            "hostname":   "vc01.example.org",
            "name":       "MyCluster",
        }
    """
    logger.info(
        '[%s] Getting Datacenter using Cluster %s',
        agent.host,
        msg['name']
    )

    # Find the HostSystem by it's 'name' property
    # and get the Datacenter object using it
    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=['name', 'parent'],
        obj_type=pyVmomi.vim.ClusterComputeResource,
        obj_property_name='name',
        obj_property_value=msg['name']
    )

    if data['success'] != 0:
        return data

    # Get properties from the result
    props = data['result'][0]
    obj_datacenter = props['parent']

    # walk the parent heirarchy until the datacenter parent is found
    obj_datacenter = [_parent_recurse(obj_datacenter, 'pyVmomi.VmomiSupport.vim.Datacenter')]

    # Get a list view of the Datacenter from this VirtualMachine object
    # and collect their properties
    view_ref = agent.get_list_view(obj=obj_datacenter)
    result = agent.collect_properties(
        view_ref=view_ref,
        obj_type=pyVmomi.vim.Datacenter,
        path_set=['name']
    )

    view_ref.DestroyView()

    r = {
        'success': 0,
        'msg': 'Successfully discovered objects',
        'result': result,
    }

    return r


@task(name='cluster.perf.metrics.get', required=['name', 'counter-name', 'perf-interval'])
def cluster_perf_metrics_get(agent, msg):
    """
    Get performance metrics for a vim.ClusterComputeResource managed object

    A vim.ClusterComputeResource managed entity supports historical
    statistics only, so make sure to provide a valid historical
    performance interval as part of the client message.

    Example client message would be:

    {
        "method":   "cluster.perf.metrics.get",
        "hostname": "vc01.example.org",
        "name":     "MyCluster",
        "counter-name": clusterServices.effectivemem.megaBytes  # Effective memory resources
        "perf-interval": "Past day"  # Historical performance interval
    }

    Returns:
        The retrieved performance metrics

    """
    obj = agent.get_object_by_property(
        property_name='name',
        property_value=msg['name'],
        obj_type=pyVmomi.vim.ClusterComputeResource
    )

    if not obj:
        return {'success': 1, 'msg': 'Cannot find object: {}'.format(msg['name'])}

    counter_name = msg.get('counter-name')
    interval_name = msg.get('perf-interval')

    return _entity_perf_metrics_get(
        agent=agent,
        entity=obj,
        counter_name=counter_name,
        interval_name=interval_name
    )


def _folder_recurse(obj, filter_for_type):
    ret = []
    for child_entity in obj.childEntity:
        child_entity_type = str(type(child_entity))
        if filter_for_type in child_entity_type:
            ret.append(child_entity)
        elif 'pyVmomi.VmomiSupport.vim.Folder' in child_entity_type:
            ret.extend(_folder_recurse(child_entity, filter_for_type))

    return ret


def _parent_recurse(obj, filter_for_type):
    if obj is None or filter_for_type in str(type(obj)):
        return obj
    else:
        return _parent_recurse(obj.parent, filter_for_type)


@task(name='datacenter.get', required=['name', 'properties'])
def datacenter_get(agent, msg):
    """
    Get properties of a single vim.Datacenter managed object

    Example client message would be:

    {
        "method":     "datacenter.get",
        "hostname":   "vc01.example.org",
        "name":       "MyDatacenter",
        "properties": [
            "name",
            "overallStatus"
        ]
    }

    Returns:
        The managed object properties in JSON format

    """
    # Property names to be collected
    properties = ['name']
    if 'properties' in msg and msg['properties']:
        properties.extend(msg['properties'])

    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=properties,
        obj_type=pyVmomi.vim.Datacenter,
        obj_property_name='name',
        obj_property_value=msg['name']
    )

    if data.get('result') is not None:
        if 'triggeredAlarmState' in properties:
            triggeredAlarmState = data['result'][0].get('triggeredAlarmState')

            alarms = []
            alarm_count = 0
            alarms_filtered = []
            alarm_filtered_count = 0
            if triggeredAlarmState is not None:

                filteredAlarms = [
                    re.compile('^Host CPU usage$', re.IGNORECASE),
                    re.compile('^Host memory usage$', re.IGNORECASE),
                    re.compile('^Virtual machine CPU usage$', re.IGNORECASE),
                    re.compile('^Virtual machine memory usage$', re.IGNORECASE),
                ]

                for triggeredAlarm in triggeredAlarmState:
                    alarm_name = triggeredAlarm.alarm.info.name
                    alarm_desc = triggeredAlarm.alarm.info.description
                    entity = triggeredAlarm.entity.name
                    key = triggeredAlarm.key
                    filtered = False
                    for filteredAlarm in filteredAlarms:
                        if filteredAlarm.match(alarm_name):
                            filtered = True
                            alarm_filtered_count += 1
                            alarms_filtered.append(entity + ' - ' + key + ' - ' + alarm_name + ' - ' + alarm_desc)
                            break
                    if filtered:
                        continue
                    else:
                        alarm_count += 1
                        alarms.append(entity + ' - ' + key + ' - ' + alarm_name + ' - ' + alarm_desc)

                data['result'][0]['triggeredAlarmState'] = '\n'.join(alarms)
                data['result'][0]['triggeredAlarmFilteredState'] = '\n'.join(alarms_filtered)
            else:
                data['result'][0]['triggeredAlarmState'] = ''
                data['result'][0]['triggeredAlarmFilteredState'] = ''

            data['result'][0]['triggeredAlarmCount'] = alarm_count
            data['result'][0]['triggeredAlarmFilteredCount'] = alarm_filtered_count

    return data


@task(name='datacenter.vm.get', required=['name'])
def datacenter_vm_get(agent, msg):
    """
    Get all VirtualMachine objects attached to a specific Datacenter
    Example client message would be:
        {
            "method":     "datacenter.host.get",
            "hostname":   "vc01.example.org",
            "name":       "MyDatacenter",
        }
    """
    logger.info(
        '[%s] Getting VirtualMachine list using Datacenter %s',
        agent.host,
        msg['name']
    )

    # Find the Datacenter by it's 'name' property
    # and get the HostSystem objects using it
    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=['name', 'vmFolder'],
        obj_type=pyVmomi.vim.Datacenter,
        obj_property_name='name',
        obj_property_value=msg['name']
    )

    if data['success'] != 0:
        return data

    # Get properties from the result
    props = data['result'][0]
    obj_vm = props['vmFolder']

    # obj_host is a Folder object of VirtualMachine and other Folders,
    # but we need a list of VirtualMachine ones instead
    obj_vm = _folder_recurse(obj_vm, 'pyVmomi.VmomiSupport.vim.VirtualMachine')

    # Get a list view of the hosts from this datacenter object
    # and collect their properties
    view_ref = agent.get_list_view(obj=obj_vm)
    result = agent.collect_properties(
        view_ref=view_ref,
        obj_type=pyVmomi.vim.VirtualMachine,
        path_set=['name']
    )

    view_ref.DestroyView()

    r = {
        'success': 0,
        'msg': 'Successfully discovered objects',
        'result': result,
    }

    return r


@task(name='datacenter.datastore.get', required=['name'])
def datacenter_datastore_get(agent, msg):
    """
    Get all Datastore objects attached to a specific Datacenter
    Example client message would be:
        {
            "method":     "datacenter.host.get",
            "hostname":   "vc01.example.org",
            "name":       "MyDatacenter",
        }
    """
    logger.info(
        '[%s] Getting Datastore list using Datacenter %s',
        agent.host,
        msg['name']
    )

    # Find the Datacenter by it's 'name' property
    # and get the HostSystem objects using it
    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=['name', 'datastore'],
        obj_type=pyVmomi.vim.Datacenter,
        obj_property_name='name',
        obj_property_value=msg['name']
    )

    if data['success'] != 0:
        return data

    # Get properties from the result
    props = data['result'][0]
    obj_datastore = props['datastore']

    # Get a list view of the hosts from this datacenter object
    # and collect their properties
    view_ref = agent.get_list_view(obj=obj_datastore)
    result = agent.collect_properties(
        view_ref=view_ref,
        obj_type=pyVmomi.vim.Datastore,
        path_set=['name']
    )

    view_ref.DestroyView()

    r = {
        'success': 0,
        'msg': 'Successfully discovered objects',
        'result': result,
    }

    return r


@task(name='datacenter.cluster.get', required=['name'])
def datacenter_cluster_get(agent, msg):
    """
    Get all ClusterComputeResource objects attached to a specific Datacenter
    Example client message would be:
        {
            "method":     "datacenter.host.get",
            "hostname":   "vc01.example.org",
            "name":       "MyDatacenter",
        }
    """
    logger.info(
        '[%s] Getting ClusterComputeResource list using Datacenter %s',
        agent.host,
        msg['name']
    )

    # Find the Datacenter by it's 'name' property
    # and get the HostSystem objects using it
    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=['name', 'hostFolder'],
        obj_type=pyVmomi.vim.Datacenter,
        obj_property_name='name',
        obj_property_value=msg['name']
    )

    if data['success'] != 0:
        return data

    # Get properties from the result
    props = data['result'][0]
    obj_host = props['hostFolder']

    # obj_host is a Folder object,
    # but we need a list of HostSystem ones instead
    obj_host = obj_host.childEntity

    # Get a list view of the hosts from this datacenter object
    # and collect their properties
    view_ref = agent.get_list_view(obj=obj_host)
    result = agent.collect_properties(
        view_ref=view_ref,
        obj_type=pyVmomi.vim.ClusterComputeResource,
        path_set=['name']
    )

    view_ref.DestroyView()

    r = {
        'success': 0,
        'msg': 'Successfully discovered objects',
        'result': result,
    }

    return r


@task(name='datacenter.host.get', required=['name'])
def datacenter_host_get(agent, msg):
    """
    Get all HostSystem objects attached to a specific Datacenter
    Example client message would be:
        {
            "method":     "datacenter.host.get",
            "hostname":   "vc01.example.org",
            "name":       "MyDatacenter",
        }
    """
    logger.info(
        '[%s] Getting HostSystem list using Datacenter %s',
        agent.host,
        msg['name']
    )

    # Find the Datacenter by it's 'name' property
    # and get the HostSystem objects using it
    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=['name', 'hostFolder'],
        obj_type=pyVmomi.vim.Datacenter,
        obj_property_name='name',
        obj_property_value=msg['name']
    )

    if data['success'] != 0:
        return data

    # Get properties from the result
    props = data['result'][0]
    obj_host = props['hostFolder']

    # obj_host is a Folder object,
    # but we need a list of HostSystem ones instead
    obj_host = obj_host.childEntity

    # obj_host is a list of ClusterComputeResource[] objects,
    # but we need a list of HostSystem ones instead
    obj_host = [item for sublist in [h.host for h in obj_host] for item in sublist]

    # Get a list view of the hosts from this datacenter object
    # and collect their properties
    view_ref = agent.get_list_view(obj=obj_host)
    result = agent.collect_properties(
        view_ref=view_ref,
        obj_type=pyVmomi.vim.HostSystem,
        path_set=['name']
    )

    view_ref.DestroyView()

    r = {
        'success': 0,
        'msg': 'Successfully discovered objects',
        'result': result,
    }

    return r


@task(name='datacenter.perf.metrics.get', required=['name', 'counter-name', 'perf-interval'])
def datacenter_perf_metrics_get(agent, msg):
    """
    Get performance metrics for a vim.Datacenter managed object

    A vim.Datacenter managed entity supports historical performance
    metrics only, so a valid historical performance interval
    should be provided as part of the client message.

    Example client message would be:

    {
        "method":   "datacenter.perf.metrics.get",
        "hostname": "vc01.example.org",
        "name":     "MyDatacenter",
        "counter-name": vmop.numPoweron.number  # VM power on count
        "perf-interval": "Past day"  # Historical performance interval
    }

    Returns:
        The retrieved performance metrics

    """
    obj = agent.get_object_by_property(
        property_name='name',
        property_value=msg['name'],
        obj_type=pyVmomi.vim.Datacenter
    )

    if not obj:
        return {'success': 1, 'msg': 'Cannot find object: {}'.format(msg['name'])}

    counter_name = msg.get('counter-name')
    interval_name = msg.get('perf-interval')

    return _entity_perf_metrics_get(
        agent=agent,
        entity=obj,
        counter_name=counter_name,
        interval_name=interval_name
    )


@task(name='datastore.get', required=['name', 'properties'])
def datastore_get(agent, msg):
    """
    Get properties for a vim.Datastore managed object

    Example client message would be:

        {
            "method":     "datastore.get",
            "hostname":   "vc01.example.org",
            "name":       "ds:///vmfs/volumes/643f118a-a970df28/",
            "properties": [
                "name",
                "summary.accessible",
                "summary.capacity"
            ]
        }

    Returns:
        The managed object properties in JSON format

    """
    # Property names to be collected
    properties = ['name', 'info.url']
    if 'properties' in msg and msg['properties']:
        properties.extend(msg['properties'])

    properties_readd = []
    properties_remove = []
    if 'host.key.config.fileSystemVolume.mountInfo.volume.extent' in properties:
        properties_readd.append('host.key.config.fileSystemVolume.mountInfo.volume.extent')
        properties.remove('host.key.config.fileSystemVolume.mountInfo.volume.extent')

        if 'host' not in properties:
            properties.extend(['host'])
            properties_remove.append('host')

    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=properties,
        obj_type=pyVmomi.vim.Datastore,
        obj_property_name='info.url',
        obj_property_value=msg['name']
    )

    for property_remove in properties_remove:
        properties.remove(property_remove)
    properties.extend(properties_readd)

    if data.get('result') is not None:
        dspath = data['result'][0]['info.url'][5:][:-1]
        if 'host.key.config.fileSystemVolume.mountInfo.volume.extent' in properties:
            extents = []
            hosts_data = data['result'][0].get('host')
            if hosts_data is None:
                hosts_data = []
            for host in hosts_data:
                # this is faster by far than just walking the path....
                data_host = vpoller.vsphere.tasks._get_object_properties(
                    agent=agent,
                    properties=['name', 'config.fileSystemVolume.mountInfo', 'config.storageDevice.scsiLun'],
                    obj_type=pyVmomi.vim.HostSystem,
                    obj_property_name='name',
                    obj_property_value=host.key.name
                )
                if data_host.get('result') is not None:
                    for mountInfo in data_host['result'][0]['config.fileSystemVolume.mountInfo']:
                        if mountInfo.mountInfo.path == dspath:
                            if mountInfo.volume.type == 'NFS':
                                extents.append({
                                                   'diskName': 'NFS_' + mountInfo.volume.remoteHost + '_' + mountInfo.volume.remotePath.replace(
                                                       '/', '_'), 'storageHost': mountInfo.volume.remoteHost,
                                                   'lun': mountInfo.volume.remotePath, 'partition': '',
                                                   'type': mountInfo.volume.type})
                            else:
                                for extent in mountInfo.volume.extent:
                                    extents.append({'diskName': extent.diskName, 'partition': extent.partition,
                                                    'type': mountInfo.volume.type})
                                break
                break
            data['result'][0]['host.key.config.fileSystemVolume.mountInfo.volume.extent'] = extents

        if 'host' in properties:
            hosts = []
            hosts_data = data['result'][0].get('host')
            if hosts_data is None:
                hosts_data = []
            for host in hosts_data:
                hosts.append(host.key.name)
            data['result'][0]['host'] = hosts
        else:
            del data['result'][0]['host']

        if 'vm' in properties:
            vms = []
            vms_data = data['result'][0].get('vm')
            if vms_data is None:
                vms_data = []
            for vm in vms_data:
                vms.append(vm.name)

            data['result'][0]['vm'] = vms

        if 'triggeredAlarmState' in properties:
            triggeredAlarmState = data['result'][0].get('triggeredAlarmState')

            alarms = []
            alarm_count = 0
            alarms_filtered = []
            alarm_filtered_count = 0
            if triggeredAlarmState is not None:

                filteredAlarms = [
                    re.compile('^Datastore usage on disk$', re.IGNORECASE),
                ]

                for triggeredAlarm in triggeredAlarmState:
                    alarm_name = triggeredAlarm.alarm.info.name
                    alarm_desc = triggeredAlarm.alarm.info.description
                    entity = triggeredAlarm.entity.name
                    key = triggeredAlarm.key
                    filtered = False
                    for filteredAlarm in filteredAlarms:
                        if filteredAlarm.match(alarm_name):
                            filtered = True
                            alarm_filtered_count += 1
                            alarms_filtered.append(entity + ' - ' + key + ' - ' + alarm_name + ' - ' + alarm_desc)
                            break
                    if filtered:
                        continue
                    else:
                        alarm_count += 1
                        alarms.append(entity + ' - ' + key + ' - ' + alarm_name + ' - ' + alarm_desc)

                data['result'][0]['triggeredAlarmState'] = '\n'.join(alarms)
                data['result'][0]['triggeredAlarmFilteredState'] = '\n'.join(alarms_filtered)
            else:
                data['result'][0]['triggeredAlarmState'] = ''
                data['result'][0]['triggeredAlarmFilteredState'] = ''

            data['result'][0]['triggeredAlarmCount'] = alarm_count
            data['result'][0]['triggeredAlarmFilteredCount'] = alarm_filtered_count

    return data


@task(name='datastore.host.get', required=['name'])
def datastore_host_get(agent, msg):
    raise ValueError('Use datastore.get with -p host instead...')


@task(name='datastore.vm.get', required=['name'])
def datastore_vm_get(agent, msg):
    raise ValueError('Use datastore.get with -p vm instead...')


@task(name='datastore.perf.metrics.get', required=['name', 'counter-name'])
def datastore_perf_metrics_get(agent, msg):
    """
    Get performance metrics for a vim.Datastore managed object

    The properties passed in the message are the performance
    counter IDs to be retrieved.

    Example client message would be:

        {
            "method":     "datastore.perf.metrics.get",
            "hostname":   "vc01.example.org",
            "name":       "ds:///vmfs/volumes/643f118a-a970df28/",
            "counter-id": "datastore.numberReadAveraged.number"
        }

    For historical performance statistics make sure to pass the
    performance interval as part of the message, e.g.:

        {
            "method":   "datastore.perf.metrics.get",
            "hostname": "vc01.example.org",
            "name":     "ds:///vmfs/volumes/643f118a-a970df28/",
            "properties": "datastore.numberReadAveraged.number",
            "perf-interval": "Past day"
        }

    Returns:
        The retrieved performance metrics

    """
    data_ds = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=['summary.datastore', 'name', 'info.url', 'host'],
        obj_type=pyVmomi.vim.Datastore,
        obj_property_name='info.url',
        obj_property_value=msg['name']
    )

    if data_ds.get('result') is not None and len(data_ds.get('result')) < 1:
        return {'success': 1, 'msg': 'Cannot find object: {}'.format(msg['name'])}

    try:
        counter_name = msg.get('counter-name').split(',')
        if 'disk.capacity.bytes.latest' in counter_name:
            counter_name.remove('disk.capacity.bytes.latest')
        counter_name = ','.join(counter_name)

        max_sample = int(msg.get('max-sample')) if msg.get('max-sample') else 1
        interval_name = msg.get('perf-interval')
        instance = msg.get('instance') if msg.get('instance') else ''
    except (TypeError, ValueError):
        logger.warning('Invalid message, cannot retrieve performance metrics')
        return {
            'success': 1,
            'msg': 'Invalid message, cannot retrieve performance metrics'
        }

    data = _entity_perf_metrics_get(
        agent=agent,
        entity=data_ds['result'][0]['summary.datastore'],
        counter_name=counter_name,
        max_sample=max_sample,
        instance=instance,
        interval_name=interval_name
    )

    if data.get('result') is not None:
        if 'disk.capacity.bytes.latest' in msg['counter-name'].split(','):
            # get instance name:
            disk_name = ''
            for metric in data['result']:
                disk_name = metric['instance']
                if disk_name != '':
                    break

            if disk_name != '':
                hosts_data = data_ds['result'][0]['host']
                if hosts_data is None:
                    hosts_data = []
                for host in hosts_data:
                    # this is faster by far than just walking the path....
                    data_host = vpoller.vsphere.tasks._get_object_properties(
                        agent=agent,
                        properties=['name', 'config.storageDevice.scsiLun'],
                        obj_type=pyVmomi.vim.HostSystem,
                        obj_property_name='name',
                        obj_property_value=host.key.name
                    )
                    if data_host.get('result') is not None:
                        for scsiLun in data_host['result'][0]['config.storageDevice.scsiLun']:
                            if scsiLun.canonicalName == disk_name:
                                capacity = getattr(scsiLun, 'capacity')
                                capacity_bytes = getattr(capacity, 'block') * getattr(capacity, 'blockSize')
                                data['result'].append({'instance': disk_name, 'counterId': 'disk.capacity.bytes.latest',
                                                       'value': capacity_bytes,
                                                       'timestamp': '%Y-%m-%d %H:%M:%S+00:00'.format(
                                                           datetime.datetime.now())})
                    break

    return data


@task(name='resource.pool.cluster.get', required=['name'])
def resource_pool_cluster_get(agent, msg):
    """
    Get the Cluster objects attached to a specific ResourcePool
    Example client message would be:
        {
            "method":     "resource.pool.cluster.get",
            "hostname":   "vc01.example.org",
            "name":       "MyResourcePool",
        }
    """
    logger.info(
        '[%s] Getting Cluster using ResourcePool %s',
        agent.host,
        msg['name']
    )

    # Find the ResourcePool by it's 'name' property
    # and get the Cluster object using it
    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=['name', 'owner'],
        obj_type=pyVmomi.vim.ResourcePool,
        obj_property_name='name',
        obj_property_value=msg['name']
    )

    if data['success'] != 0:
        return data

    # Get properties from the result
    props = data['result'][0]
    obj_cluster = [props['owner']]

    # Get a list view of the Cluster from this ResourcePool object
    # and collect their properties
    view_ref = agent.get_list_view(obj=obj_cluster)
    result = agent.collect_properties(
        view_ref=view_ref,
        obj_type=pyVmomi.vim.ClusterComputeResource,
        path_set=['name']
    )

    view_ref.DestroyView()

    r = {
        'success': 0,
        'msg': 'Successfully discovered objects',
        'result': result,
    }

    return r


@task(name='datastore.datacenter.get', required=['name'])
def datastore_datacenter_get(agent, msg):
    raise ValueError('Use datastore.get with -p datacenter (needs implemented) instead...')
    """
    Get the Datacenter object attached to a specific Datastore
    Example client message would be:
        {
            "method":     "host.datacenter.get",
            "hostname":   "vc01.example.org",
            "name":       "MyDatastore",
        }
    """
    logger.info(
        '[%s] Getting Datacenter using Datastore %s',
        agent.host,
        msg['name']
    )

    # Find the Datastore by it's 'name' property
    # and get the Datacenter object using it
    data = vpoller.vsphere.tasks._get_object_properties(
        agent=agent,
        properties=['name', 'parent'],
        obj_type=pyVmomi.vim.Datastore,
        obj_property_name='name',
        obj_property_value=msg['name']
    )

    if data['success'] != 0:
        return data

    # Get properties from the result
    props = data['result'][0]
    obj_datacenter = props['parent']

    # walk the parent heirarchy until the datacenter parent is found
    obj_datacenter = [_parent_recurse(obj_datacenter, 'pyVmomi.VmomiSupport.vim.Datacenter')]

    # Get a list view of the Datacenter from this VirtualMachine object
    # and collect their properties
    view_ref = agent.get_list_view(obj=obj_datacenter)
    result = agent.collect_properties(
        view_ref=view_ref,
        obj_type=pyVmomi.vim.Datacenter,
        path_set=['name']
    )

    view_ref.DestroyView()

    r = {
        'successs': 0,
        'msg': 'Successfully discovered objects',
        'result': result,
    }

    return r


@task(name='vsan.usage.get')
def vsan_usage_get(agent, msg):
    """
    Args:
        agent:
        msg:

    Returns:

    """
    client = vsan.client(msg['hostname'], msg['username'], msg['password'], msg['name'])
    result = client.usage()
    r = {
        'successs': 0,
        'msg': 'Successfully discovered objects',
        'result': result,
    }
    return r


@task(name='vsan.health.get')
def vsan_health_get(agent, msg):
    """
    Args:
        agent:
        msg:

    Returns:

    """
    client = vsan.client(msg['hostname'], msg['username'], msg['password'], msg['name'])
    result = client.health()
    r = {
        'successs': 0,
        'msg': 'Returning the vSan health',
        'result': result,
    }
    print result
    return r

@task(name='vsan.config.get')
def vsan_config_get(agent, msg):
    """
    Args:
        agent:
        msg:

    Returns:

    """
    client = vsan.client(msg['hostname'], msg['username'], msg['password'], msg['name'])
    result = client.config()
    r = {
        'successs': 0,
        'msg': 'Returning the vSan config',
        'result': result,
    }
    return r




