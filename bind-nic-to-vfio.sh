#!/bin/bash
set -e

if [[ "$1" == "" ]]; then
    echo "Usage: sudo $0 <interface_name>"
    exit
fi

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root" 1>&2
    exit 1
fi

INTERFACE="$1"
BDF="$(ethtool -i $INTERFACE | grep bus-info)"
BDF="${BDF##bus-info: }"  # I hate BASH string manipulation gibberish
IOMMU_GROUP="$(lspci -vs $BDF | grep IOMMU\ group)"
IOMMU_GROUP="${IOMMU_GROUP##*IOMMU group }"
echo "Interface:   $INTERFACE"
echo "BusDevFunc:  $BDF"
echo "IOMMU Group: $IOMMU_GROUP"

modprobe vfio-pci
echo $BDF > /sys/bus/pci/devices/$BDF/driver/unbind
echo vfio-pci > /sys/bus/pci/devices/$BDF/driver_override
echo $BDF > /sys/bus/pci/drivers_probe

chown `whoami`: /dev/vfio/$IOMMU_GROUP
lspci -vnn -s $BDF

