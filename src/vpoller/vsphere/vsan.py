import ssl
import sys

from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim, SoapStubAdapter
#import vsanmgmtObjects  # must be imported to init vim with vsan stuff

VSAN_API_VC_SERVICE_ENDPOINT = '/vsanHealth'
VSAN_API_ESXI_SERVICE_ENDPOINT = '/vsan'
VERSION = 'vim.version.version10'

HEALTH_MAP = { 'grey': 0, 'green': 1, 'yellow': 2, 'red': 3 }


class client():
  def __init__( self, hostname, username, password, location ):
    context = ssl._create_unverified_context()
    self.si = SmartConnect(host=hostname, user=username, pwd=password, port=443, sslContext=context)

    content = self.si.RetrieveContent()
    aboutInfo = content.about
    if aboutInfo.apiType != 'VirtualCenter':
      raise ValueError( 'Only works with vcenter' )

    majorApiVersion = aboutInfo.apiVersion.split('.')[0]
    if int( majorApiVersion ) < 6:
      raise ValueError( 'Requires vCneter 6.0 or greater' )

    parts = location.split( '/' )
    if len( parts ) != 4 or parts[2] != 'host':
      raise ValueError( 'Invalid location' )

    self.dc = None
    for self.dc in content.rootFolder.childEntity:
      if self.dc.name == parts[1]:
        break

    if self.dc is None:
      raise ValueError( 'Unable to find DataCenter "{0}"'.format( parts[1] ) )

    self.cluster = None

    for self.cluster in self.dc.hostFolder.childEntity:
      if self.cluster.name == parts[3]:
        break

    if self.cluster is None:
      raise ValueError( 'Unable to find Cluster "{0}" in Datacenter "{1}"'.format( parts[3], parts[1] ) )

    self.vsanStub = SoapStubAdapter(host=hostname, path=VSAN_API_VC_SERVICE_ENDPOINT, version=VERSION, sslContext=context)
    self.vsanStub.cookie = self.si._stub.cookie

  def disconnect( self ):
    Disconnect( self.si )

  def health( self ):
    result = {}
    vhs = vim.cluster.VsanVcClusterHealthSystem( 'vsan-cluster-health-system', self.vsanStub )
    rc = vhs.QueryClusterHealthSummary( cluster=self.cluster, includeObjUuids=True, fetchFromCache=True, fields=[ 'overallHealth', 'clusterStatus' ] )

    result[ 'vsan.health.overall' ] = HEALTH_MAP[ rc.overallHealth.lower() ]
    result[ 'vsan.cluster.status' ] = HEALTH_MAP[ rc.clusterStatus.status.lower() ]

    result[ 'vsan.host.status' ] = []
    for host in rc.clusterStatus.trackedHostsStatus:
      result[ 'vsan.host.status' ].append( ( host.hostname, HEALTH_MAP[ host.status.lower() ] ) )

    return result

  def usage( self ):
    result = {}
    vrs = vim.cluster.VsanSpaceReportSystem( 'vsan-cluster-space-report-system', self.vsanStub )
    rc = vrs.VsanQuerySpaceUsage(cluster=self.cluster).spaceOverview

    for item in ( 'overheadB', 'temporaryOverheadB', 'primaryCapacityB', 'provisionCapacityB', 'reservedCapacityB', 'overReservedB', 'physicalUsedB', 'usedB' ):
      result[ 'vsan.usage.{0}'.format( item ) ] = rc.__dict__[ item ]
      print

    return result



  def config(self):
    result = {}
    vcs = vim.cluster.VsanVcClusterConfigSystem('vsan-cluster-config-system', self.vsanStub)
    rc = vcs.VsanClusterGetConfig(cluster=self.cluster)
    #print self.cluster.host
    hostProps = self.CollectMultiple(self.cluster.host,
                                     ['name', 'configManager.vsanSystem', 'configManager.storageSystem'])

    hosts = hostProps.keys()
    print hostProps
    for host in hosts:
      dd = hostProps[host]['configManager.vsanSystem'].QueryDisksForVsan()
      #print dd

    vcs1 = vim.cluster.VsanVcDiskManagementSystem('vsan-disk-management-system',self.vsanStub)
    print 'Display disk groups in each host'
    for host in hosts:
        diskMaps = vcs1.QueryDiskMappings(host)
        print diskMaps
    return dd

  def CollectMultiple( self, objects, parameters, handleNotFound=True):
    content = self.si.content
    # print objects
    if len(objects) == 0:
      return {}
    result = None
    pc = content.propertyCollector
    propSet = [vim.PropertySpec(
      type=objects[0].__class__,
      pathSet=parameters
    )]

    while result == None and len(objects) > 0:
      try:
        objectSet = []
        for obj in objects:
          objectSet.append(vim.ObjectSpec(obj=obj))
        specSet = [vim.PropertyFilterSpec(objectSet=objectSet, propSet=propSet)]
        result = pc.RetrieveProperties(specSet=specSet)
      except vim.ManagedObjectNotFound as ex:
        objects.remove(ex.obj)
        result = None

    out = {}
    for x in result:
      out[x.obj] = {}
      for y in x.propSet:
        out[x.obj][y.name] = y.val
    return out