#
# Copyright(c) 2019-2022 Intel Corporation
# Copyright(c) 2024 Huawei Technologies
# SPDX-License-Identifier: BSD-3-Clause
#

from ctypes import (
    c_uint64,
    c_uint32,
    c_uint16,
    c_int,
    c_char,
    c_char_p,
    c_void_p,
    c_bool,
    c_uint8,
    Structure,
    byref,
    cast,
    create_string_buffer,
    POINTER,
)
from enum import IntEnum, auto
from datetime import timedelta
import re

from ..ocf import OcfLib
from .shared import (
    Uuid,
    OcfError,
    OcfErrorCode,
    CacheLineSize,
    CacheLines,
    OcfCompletion,
    SeqCutOffPolicy,
)
from ..utils import Size, struct_to_dict
from .core import Core
from .queue import Queue
from .stats.cache import CacheInfo
from .io import IoDir
from .ioclass import IoClassesInfo, IoClassInfo
from .stats.shared import UsageStats, RequestsStats, BlocksStats, ErrorsStats
from .ctx import OcfCtx
from .volume import RamVolume, Volume


class Backfill(Structure):
    _fields_ = [("_max_queue_size", c_uint32), ("_queue_unblock_size", c_uint32)]


class CacheMetadataSegment(IntEnum):
    _ignore_ = "name_mapping"
    SB_CONFIG = 0
    SB_RUNTIME = auto()
    RESERVED = auto()
    PART_CONFIG = auto()
    PART_RUNTIME = auto()
    CORE_CONFIG = auto()
    CORE_RUNTIME = auto()
    CORE_UUID = auto()
    CLEANING = auto()
    LRU = auto()
    COLLISION = auto()
    LIST_INFO = auto()
    HASH = auto()

    @classmethod
    def segment_in_text(cls, log):
        name_mapping = {
            "Super block config": cls.SB_CONFIG,
            "Super block runtime": cls.SB_RUNTIME,
            "Reserved": cls.RESERVED,
            "Part config": cls.PART_CONFIG,
            "Part runtime": cls.PART_RUNTIME,
            "Core config": cls.CORE_CONFIG,
            "Core runtime": cls.CORE_RUNTIME,
            "Core UUID": cls.CORE_UUID,
            "Cleaning": cls.CLEANING,
            "LRU": cls.LRU,
            "Collision": cls.COLLISION,
            "List info": cls.LIST_INFO,
            "Hash": cls.HASH,
        }

        for name, segment in name_mapping.items():
            match = re.search(name, log)
            if match:
                return segment

        return None


class CacheConfig(Structure):
    MAX_CACHE_NAME_SIZE = 32
    _fields_ = [
        ("_name", c_char * MAX_CACHE_NAME_SIZE),
        ("_cache_mode", c_uint32),
        ("_promotion_policy", c_uint32),
        ("_cache_line_size", c_uint64),
        ("_metadata_volatile", c_bool),
        ("_locked", c_bool),
        ("_pt_unaligned_io", c_bool),
        ("_use_submit_io_fast", c_bool),
        ("_backfill", Backfill),
    ]


class CacheDeviceConfig(Structure):
    _fields_ = [
        ("_volume", c_void_p),
        ("_perform_test", c_bool),
        ("_volume_params", c_void_p),
    ]


class CacheAttachConfig(Structure):
    _fields_ = [
        ("_device", CacheDeviceConfig),
        ("_cache_line_size", c_uint64),
        ("_open_cores", c_bool),
        ("_force", c_bool),
        ("_discard_on_start", c_bool),
        ("_disable_cleaner", c_bool),
    ]


class CacheStandbyActivateConfig(Structure):
    _fields_ = [
        ("_device", CacheDeviceConfig),
        ("_open_cores", c_bool),
    ]


class ConfValidValues:
    promotion_nhit_insertion_threshold_range = range(2, 1000)
    promotion_nhit_trigger_threshold_range = range(0, 100)

    cleaning_alru_wake_up_time_range = range(0, 3600)
    cleaning_alru_staleness_time_range = range(1, 3600)
    cleaning_alru_flush_max_buffers_range = range(1, 10000)
    cleaning_alru_activity_threshold_range = range(0, 1000000)

    cleaning_acp_wake_up_time_range = range(0, 10000)
    cleaning_acp_flush_max_buffers_range = range(1, 10000)

    seq_cutoff_threshold_rage = range(1, 4294841344)
    seq_cutoff_promotion_range = range(1, 65535)

    ioclass_id_range = range(0, 32)
    ioclass_priority_range = range(-1, 255)
    ioclass_min_size_range = range(0, 100)
    ioclass_max_size_range = range(0, 100)


CACHE_MODE_NONE = -1


class CacheMode(IntEnum):
    WT = 0
    WB = 1
    WA = 2
    PT = 3
    WI = 4
    WO = 5
    DEFAULT = WT

    def lazy_write(self):
        return self.value in [CacheMode.WB, CacheMode.WO]

    def write_insert(self):
        return self.value not in [CacheMode.PT, CacheMode.WA, CacheMode.WI]

    def read_insert(self):
        return self.value not in [CacheMode.PT, CacheMode.WO]


class PromotionPolicy(IntEnum):
    ALWAYS = 0
    NHIT = 1
    DEFAULT = ALWAYS


class NhitParams(IntEnum):
    INSERTION_THRESHOLD = 0
    TRIGGER_THRESHOLD = 1


class CleaningPolicy(IntEnum):
    NOP = 0
    ALRU = 1
    ACP = 2
    DEFAULT = ALRU


class AlruParams(IntEnum):
    WAKE_UP_TIME = 0
    STALE_BUFFER_TIME = 1
    FLUSH_MAX_BUFFERS = 2
    ACTIVITY_THRESHOLD = 3


class AcpParams(IntEnum):
    WAKE_UP_TIME = 0
    FLUSH_MAX_BUFFERS = 1


class MetadataLayout(IntEnum):
    STRIPING = 0
    SEQUENTIAL = 1
    DEFAULT = STRIPING


class Cache:
    DEFAULT_BACKFILL_QUEUE_SIZE = 65536
    DEFAULT_BACKFILL_UNBLOCK = 60000
    DEFAULT_PT_UNALIGNED_IO = False
    DEFAULT_USE_SUBMIT_FAST = False

    def __init__(
        self,
        owner,
        name: str = "cache",
        cache_mode: CacheMode = CacheMode.DEFAULT,
        promotion_policy: PromotionPolicy = PromotionPolicy.DEFAULT,
        cache_line_size: CacheLineSize = CacheLineSize.DEFAULT,
        metadata_volatile: bool = False,
        max_queue_size: int = DEFAULT_BACKFILL_QUEUE_SIZE,
        queue_unblock_size: int = DEFAULT_BACKFILL_UNBLOCK,
        pt_unaligned_io: bool = DEFAULT_PT_UNALIGNED_IO,
        use_submit_fast: bool = DEFAULT_USE_SUBMIT_FAST,
    ):
        self.device = None
        self.started = False
        self.owner = owner

        self.name = name
        self.cache_mode = cache_mode
        self.promotion_policy = promotion_policy
        self.cache_line_size = cache_line_size
        self.metadata_volatile = metadata_volatile
        self.max_queue_size = max_queue_size
        self.queue_unblock_size = queue_unblock_size
        self.pt_unaligned_io = pt_unaligned_io
        self.use_submit_fast = use_submit_fast

        self.cache_handle = c_void_p()
        self._as_parameter_ = self.cache_handle
        self.io_queues = []
        self.cores = []

    def start_cache(
        self,
        init_mngmt_queue=True,
        init_default_io_queue=True,
        locked: bool = False,
    ):
        cfg = CacheConfig(
            _name=self.name.encode("ascii"),
            _cache_mode=self.cache_mode,
            _promotion_policy=self.promotion_policy,
            _cache_line_size=self.cache_line_size,
            _metadata_volatile=self.metadata_volatile,
            _backfill=Backfill(
                _max_queue_size=self.max_queue_size,
                _queue_unblock_size=self.queue_unblock_size,
            ),
            _locked=locked,
            _pt_unaligned_io=self.pt_unaligned_io,
            _use_submit_fast=self.use_submit_fast,
        )

        status = self.owner.lib.ocf_mngt_cache_start(
            self.owner.ctx_handle, byref(self.cache_handle), byref(cfg), None
        )
        if status:
            raise OcfError("Creating cache instance failed", status)

        if init_mngmt_queue:
            self.mngt_queue = Queue(
                self, "mgmt-{}".format(self.get_name()), mngt=True
            )

        if init_default_io_queue:
            self.io_queues = [Queue(self, "default-io-{}".format(self.get_name()))]
        else:
            self.io_queues = []

        self.started = True
        self.owner.caches.append(self)

    def add_io_queue(self, *args, **kwargs):
        q = Queue(self, args, **kwargs)
        self.io_queues += [q]

    def standby_detach(self):
        self.write_lock()
        c = OcfCompletion([("priv", c_void_p), ("error", c_int)])
        self.owner.lib.ocf_mngt_cache_standby_detach(self, c, None)
        c.wait()
        self.write_unlock()

        self.device = None

        if c.results["error"]:
            raise OcfError("Failed to detach failover cache device", c.results["error"])

    def standby_activate(self, device, open_cores=True):
        self.device = device
        device_cfg = self.alloc_device_config(device)

        activate_cfg = CacheStandbyActivateConfig(
            _device=device_cfg,
            _open_cores=open_cores,
        )

        self.write_lock()
        c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])
        self.owner.lib.ocf_mngt_cache_standby_activate(
            self.cache_handle, byref(activate_cfg), c, None
        )
        c.wait()
        self.write_unlock()

        self.free_device_config(device_cfg)

        if c.results["error"]:
            self.device = None
            raise OcfError("Failed to activate standby cache", c.results["error"])

    def change_cache_mode(self, cache_mode: CacheMode):
        self.write_lock()
        status = self.owner.lib.ocf_mngt_cache_set_mode(self.cache_handle, cache_mode)

        self.write_unlock()

        if status:
            raise OcfError("Error changing cache mode", status)

    def set_cleaning_policy(self, cleaning_policy: CleaningPolicy):
        self.write_lock()

        c = OcfCompletion([("priv", c_void_p), ("error", c_int)])
        self.owner.lib.ocf_mngt_cache_cleaning_set_policy(
            self.cache_handle, cleaning_policy, c, None
        )
        c.wait()

        self.write_unlock()

        if c.results["error"]:
            raise OcfError("Error changing cleaning policy", c.results["error"])

    def get_cleaning_policy(self):
        cleaning_policy = c_int()

        self.read_lock()

        status = self.owner.lib.ocf_mngt_cache_cleaning_get_policy(
            self.cache_handle, byref(cleaning_policy)
        )

        self.read_unlock()

        if status != OcfErrorCode.OCF_OK:
            raise OcfError("Failed to get cleaning policy", ret)

        return CleaningPolicy(cleaning_policy.value)

    def set_cleaning_policy_param(self, cleaning_policy: CleaningPolicy, param_id, param_value):
        self.write_lock()

        status = self.owner.lib.ocf_mngt_cache_cleaning_set_param(
            self.cache_handle, cleaning_policy, param_id, param_value
        )

        self.write_unlock()

        if status:
            raise OcfError("Error setting cleaning policy param", status)

    def set_promotion_policy(self, promotion_policy: PromotionPolicy):
        self.write_lock()

        status = self.owner.lib.ocf_mngt_cache_promotion_set_policy(
            self.cache_handle, promotion_policy
        )

        self.write_unlock()
        if status:
            raise OcfError("Error setting promotion policy", status)

    def get_promotion_policy_param(self, promotion_type, param_id):
        self.read_lock()

        param_value = c_uint64()

        status = self.owner.lib.ocf_mngt_cache_promotion_get_param(
            self.cache_handle, promotion_type, param_id, byref(param_value)
        )

        self.read_unlock()
        if status:
            raise OcfError("Error getting promotion policy parameter", status)

        return param_value

    def set_promotion_policy_param(self, promotion_type, param_id, param_value):
        self.write_lock()

        status = self.owner.lib.ocf_mngt_cache_promotion_set_param(
            self.cache_handle, promotion_type, param_id, param_value
        )

        self.write_unlock()
        if status:
            raise OcfError("Error setting promotion policy parameter", status)

    def set_seq_cut_off_policy(self, policy: SeqCutOffPolicy):
        self.write_lock()

        status = self.owner.lib.ocf_mngt_core_set_seq_cutoff_policy_all(self.cache_handle, policy)

        self.write_unlock()

        if status:
            raise OcfError("Error setting cache seq cut off policy", status)

    def set_seq_cut_off_threshold(self, threshold: int):
        self.write_lock()

        status = self.owner.lib.ocf_mngt_core_set_seq_cutoff_threshold_all(
            self.cache_handle, threshold
        )

        self.write_unlock()

        if status:
            raise OcfError("Error setting cache seq cut off policy threshold", status)

    def set_seq_cut_off_promotion(self, count: int):
        self.write_lock()

        status = self.owner.lib.ocf_mngt_core_set_seq_cutoff_promotion_count_all(
            self.cache_handle, count
        )

        self.write_unlock()

        if status:
            raise OcfError("Error setting cache seq cut off policy promotion count", status)

    def get_partition_info(self, part_id: int):
        ioclass_info = IoClassInfo()
        self.read_lock()

        status = self.owner.lib.ocf_cache_io_class_get_info(
            self.cache_handle, part_id, byref(ioclass_info)
        )

        self.read_unlock()
        if status:
            raise OcfError("Error retriving ioclass info", status)

        return {
            "_class_id": part_id,
            "_name": ioclass_info._name.decode("ascii"),
            "_cache_mode": ioclass_info._cache_mode,
            "_priority": int(ioclass_info._priority),
            "_curr_size": (ioclass_info._curr_size),
            "_min_size": int(ioclass_info._min_size),
            "_max_size": int(ioclass_info._max_size),
            "_cleaning_policy_type": int(ioclass_info._cleaning_policy_type),
        }

    def add_partition(
        self,
        part_id: int,
        name: str,
        min_size: int,
        max_size: int,
        priority: int,
        valid: bool,
    ):
        self.write_lock()

        _name = name.encode("ascii")

        status = self.owner.lib.ocf_mngt_add_partition_to_cache(
            self.cache_handle, part_id, _name, min_size, max_size, priority, valid
        )

        self.write_unlock()

        if status:
            raise OcfError("Error adding partition to cache", status)

    def configure_partition(
        self,
        part_id: int,
        name: str,
        max_size: int,
        priority: int,
        cache_mode=CACHE_MODE_NONE,
    ):
        ioclasses_info = IoClassesInfo()

        self.read_lock()

        for i in range(IoClassesInfo.MAX_IO_CLASSES):
            ioclass_info = IoClassInfo()
            status = self.owner.lib.ocf_cache_io_class_get_info(
                self.cache_handle, i, byref(ioclass_info)
            )
            if status not in [0, -OcfErrorCode.OCF_ERR_IO_CLASS_NOT_EXIST]:
                raise OcfError("Error retriving existing ioclass config", status)
            ioclasses_info._config[i]._class_id = i
            ioclasses_info._config[i]._name = (
                ioclass_info._name if len(ioclass_info._name) > 0 else 0
            )
            ioclasses_info._config[i]._priority = ioclass_info._priority
            ioclasses_info._config[i]._cache_mode = ioclass_info._cache_mode
            ioclasses_info._config[i]._max_size = ioclass_info._max_size

        self.read_unlock()

        ioclasses_info._config[part_id]._name = name.encode("utf-8")
        ioclasses_info._config[part_id]._cache_mode = int(cache_mode)
        ioclasses_info._config[part_id]._priority = priority
        ioclasses_info._config[part_id]._max_size = max_size

        self.write_lock()

        status = self.owner.lib.ocf_mngt_cache_io_classes_configure(
            self.cache_handle, byref(ioclasses_info)
        )

        self.write_unlock()

        if status:
            raise OcfError("Error adding partition to cache", status)

    def alloc_device_config(self, device, perform_test=True):
        if not device.handle:
            uuid = Uuid(
                _data=cast(create_string_buffer(device.uuid.encode("ascii")), c_char_p),
                _size=len(device.uuid) + 1,
            )
            volume = c_void_p()

            lib = OcfLib.getInstance()
            result = lib.ocf_volume_create(
                byref(volume), self.owner.ocf_volume_type[type(device)], byref(uuid)
            )

            if result != 0:
                raise OcfError("Cache volume initialization failed", result)
        else:
            volume = device.handle

        device_config = CacheDeviceConfig(
            _volume=volume,
            _perform_test=perform_test,
            _volume_params=None,
        )

        return device_config

    def free_device_config(self, cfg):
        lib = OcfLib.getInstance().ocf_volume_destroy(cfg._volume)

    def attach_device_async(
        self,
        device,
        force=False,
        perform_test=False,
        cache_line_size=None,
        open_cores=False,
        disable_cleaner=False,
    ):
        self.device = device

        device_config = self.alloc_device_config(device, perform_test=perform_test)

        attach_cfg = CacheAttachConfig(
            _device=device_config,
            _cache_line_size=cache_line_size if cache_line_size else self.cache_line_size,
            _open_cores=open_cores,
            _force=force,
            _discard_on_start=False,
            _disable_cleaner=disable_cleaner,
        )

        self.write_lock()

        def callback(c):
            self.write_unlock()
            self.free_device_config(device_config)

        c = OcfCompletion(
            [("cache", c_void_p), ("priv", c_void_p), ("error", c_int)],
            callback=callback
        )

        self.owner.lib.ocf_mngt_cache_attach(self.cache_handle, byref(attach_cfg), c, None)

        return c

    def attach_device(
        self,
        device,
        force=False,
        perform_test=False,
        cache_line_size=None,
        open_cores=False,
        disable_cleaner=False,
    ):

        c = self.attach_device_async(
            device,
            force,
            perform_test,
            cache_line_size,
            open_cores,
            disable_cleaner
        )

        c.wait()

        if c.results["error"]:
            raise OcfError(
                f"Attaching cache device failed",
                c.results["error"],
            )

    def standby_attach(self, device, force=False, disable_cleaner=False):
        self.device = device

        device_config = self.alloc_device_config(device, perform_test=False)

        attach_cfg = CacheAttachConfig(
            _device=device_config,
            _cache_line_size=self.cache_line_size,
            _open_cores=False,
            _force=force,
            _discard_on_start=False,
            _disable_cleaner=disable_cleaner,
        )

        self.write_lock()

        c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])

        self.owner.lib.ocf_mngt_cache_standby_attach(self.cache_handle, byref(attach_cfg), c, None)
        c.wait()

        self.write_unlock()

        self.free_device_config(device_config)

        if c.results["error"]:
            raise OcfError(
                f"Attaching to standby cache failed",
                c.results["error"],
            )

    def standby_load(self, device, perform_test=True, disable_cleaner=False):
        self.device = device

        device_config = self.alloc_device_config(device, perform_test=perform_test)

        attach_cfg = CacheAttachConfig(
            _device=device_config,
            _cache_line_size=self.cache_line_size,
            _open_cores=False,
            _force=False,
            _discard_on_start=False,
            _disable_cleaner=disable_cleaner,
        )

        self.write_lock()
        c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])
        self.owner.lib.ocf_mngt_cache_standby_load(self.cache_handle, byref(attach_cfg), c, None)
        c.wait()
        self.write_unlock()

        self.free_device_config(device_config)

        if c.results["error"]:
            self.device = None
            raise OcfError("Loading standby cache device failed", c.results["error"])

    def detach_device(self):
        self.write_lock()

        c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])

        self.owner.lib.ocf_mngt_cache_detach(self.cache_handle, c, None)

        c.wait()
        self.write_unlock()
        self.device = None

        if c.results["error"]:
            raise OcfError("Detaching cache device failed", c.results["error"])

    def load_cache(self, device, open_cores=True, disable_cleaner=False):
        self.device = device

        device_config = self.alloc_device_config(device)

        attach_cfg = CacheAttachConfig(
            _device=device_config,
            _cache_line_size=self.cache_line_size,
            _open_cores=open_cores,
            _force=False,
            _discard_on_start=False,
            _disable_cleaner=disable_cleaner,
        )

        self.write_lock()
        c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])
        self.owner.lib.ocf_mngt_cache_load(self.cache_handle, byref(attach_cfg), c, None)
        c.wait()
        self.write_unlock()

        self.free_device_config(device_config)

        if c.results["error"]:
            self.device = None
            raise OcfError("Loading cache device failed", c.results["error"])

    @classmethod
    def load_standby_from_device(cls, device, owner=None, name="cache", cache_line_size=None):
        if owner is None:
            owner = OcfCtx.get_default()

        c = cls(name=name, owner=owner, cache_line_size=cache_line_size)

        c.start_cache()
        try:
            c.standby_load(device)
        except:  # noqa E722
            c.stop()
            raise

        return c

    @classmethod
    def load_from_device(
        cls, device, owner=None, name="cache", open_cores=True, disable_cleaner=False
    ):
        if owner is None:
            owner = OcfCtx.get_default()

        c = cls(name=name, owner=owner)

        c.start_cache()
        try:
            c.load_cache(device, open_cores=open_cores, disable_cleaner=disable_cleaner)
        except:  # noqa E722
            c.stop()
            raise

        return c

    @classmethod
    def start_on_device(cls, device, owner=None, disable_cleaner=False, **kwargs):
        if owner is None:
            owner = OcfCtx.get_default()

        c = cls(owner=owner, **kwargs)

        c.start_cache()
        try:
            c.attach_device(device, force=True, disable_cleaner=disable_cleaner)
        except:  # noqa E722
            c.stop()
            raise

        return c

    def put(self):
        self.owner.lib.ocf_mngt_cache_put(self.cache_handle)

    def get(self):
        status = self.owner.lib.ocf_mngt_cache_get(self.cache_handle)
        if status:
            raise OcfError("Couldn't get cache instance", status)

    def read_lock(self):
        c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])
        self.owner.lib.ocf_mngt_cache_read_lock(self.cache_handle, c, None)
        c.wait()
        if c.results["error"]:
            raise OcfError("Couldn't lock cache instance", c.results["error"])

    def write_lock(self):
        c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])
        self.owner.lib.ocf_mngt_cache_lock(self.cache_handle, c, None)
        c.wait()
        if c.results["error"]:
            raise OcfError("Couldn't lock cache instance", c.results["error"])

    def read_unlock(self):
        self.owner.lib.ocf_mngt_cache_read_unlock(self.cache_handle)

    def write_unlock(self):
        self.owner.lib.ocf_mngt_cache_unlock(self.cache_handle)

    def get_core_by_name(self, name: str):
        core_handle = c_void_p()

        result = self.owner.lib.ocf_core_get_by_name(
            self.cache_handle,
            name.encode("ascii"),
            len(name),
            byref(core_handle),
        )
        if result != 0:
            raise OcfError("Failed getting core by name", result)

        uuid = self.owner.lib.ocf_core_get_uuid_wrapper(core_handle)
        device = RamVolume.get_by_uuid(uuid.contents._data.decode("ascii"))
        core = Core(device)
        core.cache = self
        core.handle = core_handle
        self.cores.append(core)

        return core

    def add_core(self, core: Core, try_add=False):
        cfg = core.get_config()

        cfg._try_add = try_add

        self.write_lock()

        c = OcfCompletion(
            [
                ("cache", c_void_p),
                ("core", c_void_p),
                ("priv", c_void_p),
                ("error", c_int),
            ]
        )

        self.owner.lib.ocf_mngt_cache_add_core(self.cache_handle, byref(cfg), c, None)

        c.wait()
        if c.results["error"]:
            self.write_unlock()
            raise OcfError("Failed adding core", c.results["error"])

        core.cache = self
        core.handle = c.results["core"]
        self.cores.append(core)

        self.write_unlock()

    def remove_core(self, core: Core):
        self.write_lock()

        c = OcfCompletion([("priv", c_void_p), ("error", c_int)])

        self.owner.lib.ocf_mngt_cache_remove_core(core.handle, c, None)

        c.wait()
        self.write_unlock()

        if c.results["error"]:
            raise OcfError("Failed removing core", c.results["error"])

        self.cores.remove(core)

    def get_front_volume(self):
        return Volume.get_instance(self.get_c_front_volume())

    def get_c_front_volume(self):
        return lib.ocf_cache_get_front_volume(self.cache_handle)

    def get_volume(self):
        return Volume.get_instance(self.get_c_volume())

    def get_c_volume(self):
        return lib.ocf_cache_get_volume(self.cache_handle)

    def get_conf(self):
        cache_info = CacheInfo()

        self.read_lock()

        status = self.owner.lib.ocf_cache_get_info(self.cache_handle, byref(cache_info))

        self.read_unlock()

        if status:
            raise OcfError("Failed getting cache info", status)

        line_size = CacheLineSize(cache_info.cache_line_size)
        cache_name = self.owner.lib.ocf_cache_get_name(self).decode("ascii")

        return {
            "attached": cache_info.attached,
            "volume_type": self.owner.volume_types[cache_info.volume_type],
            "size": CacheLines(cache_info.size, line_size),
            "inactive": {
                "occupancy": CacheLines(cache_info.inactive.occupancy.value, line_size),
                "dirty": CacheLines(cache_info.inactive.dirty.value, line_size),
                "clean": CacheLines(cache_info.inactive.clean.value, line_size),
            },
            "occupancy": CacheLines(cache_info.occupancy, line_size),
            "dirty": CacheLines(cache_info.dirty, line_size),
            "dirty_initial": CacheLines(cache_info.dirty_initial, line_size),
            "dirty_for": timedelta(seconds=cache_info.dirty_for),
            "cache_mode": CacheMode(cache_info.cache_mode),
            "fallback_pt": {
                "error_counter": cache_info.fallback_pt.error_counter,
                "status": cache_info.fallback_pt.status,
            },
            "state": cache_info.state,
            "cleaning_policy": CleaningPolicy(cache_info.cleaning_policy),
            "promotion_policy": PromotionPolicy(cache_info.promotion_policy),
            "cache_line_size": line_size,
            "flushed": CacheLines(cache_info.flushed, line_size),
            "core_count": cache_info.core_count,
            "metadata_footprint": Size(cache_info.metadata_footprint),
            "metadata_end_offset": Size(cache_info.metadata_end_offset),
            "cache_name": cache_name,
        }

    def get_stats(self):
        usage = UsageStats()
        req = RequestsStats()
        block = BlocksStats()
        errors = ErrorsStats()

        self.read_lock()

        conf = self.get_conf()

        status = self.owner.lib.ocf_stats_collect_cache(
            self.cache_handle, byref(usage), byref(req), byref(block), byref(errors)
        )

        self.read_unlock()

        if status:
            raise OcfError("Failed getting stats", status)

        return {
            "conf": conf,
            "block": struct_to_dict(block),
            "req": struct_to_dict(req),
            "usage": struct_to_dict(usage),
            "errors": struct_to_dict(errors),
        }

    def get_ioclass_stats(self, io_class_id):
        usage = UsageStats()
        req = RequestsStats()
        block = BlocksStats()

        self.read_lock()

        status = self.owner.lib.ocf_stats_collect_part_cache(
            self.cache_handle, io_class_id, byref(usage), byref(req), byref(block)
        )

        self.read_unlock()

        if status:
            raise OcfError(f"Failed to retrieve ioclass {io_class_id} stats", status)

        return {
            "usage": struct_to_dict(usage),
            "block": struct_to_dict(block),
            "req": struct_to_dict(req),
        }

    def reset_stats(self):
        self.owner.lib.ocf_core_stats_initialize_all(self.cache_handle)

    def get_default_queue(self):
        if not self.io_queues:
            raise Exception("No queues added for cache")

        return self.io_queues[0]

    def save(self):
        if not self.started:
            raise Exception("Not started!")

        self.write_lock()
        c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])
        self.owner.lib.ocf_mngt_cache_save(self.cache_handle, c, None)

        c.wait()
        self.write_unlock()

        if c.results["error"]:
            raise OcfError("Failed saving cache", c.results["error"])

    def stop(self):
        if not self.started:
            raise Exception("Already stopped!")

        self.write_lock()

        c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])

        self.owner.lib.ocf_mngt_cache_stop(self.cache_handle, c, None)

        c.wait()
        err = OcfErrorCode(-1 * c.results["error"])
        if err != OcfErrorCode.OCF_OK and err != OcfErrorCode.OCF_ERR_WRITE_CACHE:
            self.write_unlock()
            raise OcfError("Failed stopping cache", c.results["error"])

        self.mngt_queue.put()
        del self.io_queues[:]

        self.started = False
        for core in self.cores:
            core.cache = None
            core.handle = None

        self.write_unlock()
        self.device = None
        self.started = False

        self.owner.caches.remove(self)

        if err != OcfErrorCode.OCF_OK:
            raise OcfError("Failed stopping cache", c.results["error"])

    def flush(self):
        self.write_lock()

        c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])
        self.owner.lib.ocf_mngt_cache_flush(self.cache_handle, c, None)
        c.wait()
        self.write_unlock()

        if c.results["error"]:
            raise OcfError("Couldn't flush cache", c.results["error"])

    def get_name(self):
        self.read_lock()

        try:
            return str(self.owner.lib.ocf_cache_get_name(self), encoding="ascii")
        except:  # noqa E722
            raise OcfError("Couldn't get cache name")
        finally:
            self.read_unlock()

    # settle all queues accociated with this cache (mngt and I/O)
    def settle(self):
        while not self.owner.lib.ocf_dbg_cache_is_settled(self.cache_handle):
            pass

    @staticmethod
    def get_by_name(cache_name, owner=None):
        if owner is None:
            owner = OcfCtx.get_default()
        cache_pointer = c_void_p()
        return OcfLib.getInstance().ocf_mngt_cache_get_by_name(
            owner.ctx_handle, cache_name, byref(cache_pointer)
        )




lib = OcfLib.getInstance()
lib.ocf_mngt_cache_remove_core.argtypes = [c_void_p, c_void_p, c_void_p]
lib.ocf_mngt_cache_add_core.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
lib.ocf_cache_get_name.argtypes = [c_void_p]
lib.ocf_cache_get_name.restype = c_char_p
lib.ocf_cache_get_front_volume.argtypes = [c_void_p]
lib.ocf_cache_get_front_volume.restype = c_void_p
lib.ocf_cache_get_volume.argtypes = [c_void_p]
lib.ocf_cache_get_volume.restype = c_void_p
lib.ocf_mngt_cache_cleaning_get_policy.argypes = [c_void_p, POINTER(c_int)]
lib.ocf_mngt_cache_cleaning_get_policy.restype = OcfErrorCode
lib.ocf_mngt_cache_cleaning_set_policy.argtypes = [
    c_void_p,
    c_uint32,
    c_void_p,
    c_void_p,
]
lib.ocf_mngt_core_set_seq_cutoff_policy_all.argtypes = [c_void_p, c_uint32]
lib.ocf_mngt_core_set_seq_cutoff_policy_all.restype = c_int
lib.ocf_mngt_core_set_seq_cutoff_threshold_all.argtypes = [c_void_p, c_uint32]
lib.ocf_mngt_core_set_seq_cutoff_threshold_all.restype = c_int
lib.ocf_mngt_core_set_seq_cutoff_promotion_count_all.argtypes = [c_void_p, c_uint32]
lib.ocf_mngt_core_set_seq_cutoff_promotion_count_all.restype = c_int
lib.ocf_stats_collect_cache.argtypes = [
    c_void_p,
    c_void_p,
    c_void_p,
    c_void_p,
    c_void_p,
]
lib.ocf_stats_collect_cache.restype = c_int
lib.ocf_stats_collect_part_cache.argtypes = [
    c_void_p,
    c_uint16,
    c_void_p,
    c_void_p,
    c_void_p,
]
lib.ocf_stats_collect_part_cache.restype = c_int
lib.ocf_cache_get_info.argtypes = [c_void_p, c_void_p]
lib.ocf_cache_get_info.restype = c_int
lib.ocf_mngt_cache_cleaning_set_param.argtypes = [
    c_void_p,
    c_uint32,
    c_uint32,
    c_uint32,
]
lib.ocf_mngt_cache_cleaning_set_param.restype = c_int
lib.ocf_cache_io_class_get_info.restype = c_int
lib.ocf_cache_io_class_get_info.argtypes = [c_void_p, c_uint32, c_void_p]
lib.ocf_mngt_add_partition_to_cache.restype = c_int
lib.ocf_mngt_add_partition_to_cache.argtypes = [
    c_void_p,
    c_uint16,
    c_char_p,
    c_uint32,
    c_uint32,
    c_uint8,
    c_bool,
]
lib.ocf_mngt_cache_io_classes_configure.restype = c_int
lib.ocf_mngt_cache_io_classes_configure.argtypes = [c_void_p, c_void_p]
lib.ocf_volume_create.restype = c_int
lib.ocf_volume_create.argtypes = [c_void_p, c_void_p, c_void_p]
lib.ocf_volume_destroy.argtypes = [c_void_p]
