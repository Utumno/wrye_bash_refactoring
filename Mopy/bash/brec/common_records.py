# -*- coding: utf-8 -*-
#
# GPL License and Copyright Notice ============================================
#  This file is part of Wrye Bash.
#
#  Wrye Bash is free software: you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation, either version 3
#  of the License, or (at your option) any later version.
#
#  Wrye Bash is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with Wrye Bash.  If not, see <https://www.gnu.org/licenses/>.
#
#  Wrye Bash copyright (C) 2005-2009 Wrye, 2010-2020 Wrye Bash Team
#  https://github.com/wrye-bash
#
# =============================================================================
"""Builds on the rest of brec to provide full definitions and base classes for
some commonly needed records."""

from __future__ import division, print_function
from operator import attrgetter

from .mod_io import RecHeader
from .advanced_elements import FidNotNullDecider, AttrValDecider, MelArray, \
    MelUnion
from .basic_elements import MelBase, MelFid, MelFloat, MelGroups, MelLString, \
    MelNull, MelStruct, MelUInt32, MelSInt32, MelFixedString, MelGroup, \
    AttrsCompare, MelString, MelULong64
from .common_subrecords import MelEdid
from .record_structs import MelRecord, MelSet
from .utils_constants import FID
from .. import bolt, exception
from ..bolt import ChardetStr
from ..exception import StateError

#------------------------------------------------------------------------------
class _CaseSensitiveStr(ChardetStr):
    _ci_comparison = False

class _MelMaster(MelString):
    """A MelString that appends to a list of attributes"""
    _wrapper_bytes_type = ChardetStr

    def load_mel(self, record, ins, sub_type, size_, readId):
        attr_list = record.__getattribute__(self.attr, self.default)
        attr_list.append(self._wrapper_bytes_type(ins.read(size_, readId)))

class _MelMasterSize(MelULong64):

    def load_mel(self, record, ins, sub_type, size_, readId):
        attr_list = record.__getattribute__(self.attr, self.default)
        attr_list.append(ins.unpack(self._unpacker, size_, readId))

class _MelChardet(MelString):
    """Falls back to chardet to decode the string and compares case
    sensitive. **Only** use for MelAuth and MelDesc."""
    _wrapper_bytes_type = _CaseSensitiveStr

class MreHeaderBase(MelRecord):
    """File header.  Base class for all 'TES4' like records"""
    class MelMasterNames(MelGroups):
        """Handles both MAST and DATA, but turns them into two separate lists.
        This is done to make updating the master list much easier."""
        def __init__(self):
            super(MreHeaderBase.MelMasterNames, self).__init__(u'masters_info',
                _MelMaster(b'MAST', u'plugin_masters'),
                MelULong64(b'DATA', u'master_sizes'),
            )

        def getDefaulters(self, mel_set_instance, mel_key=u''):
            mel_set_instance.listers.update([u'plugin_masters', u'master_sizes'])

        def load_mel(self, record, ins, sub_type, size_, readId):
            self.loaders[sub_type].load_mel(record, ins, sub_type, size_,
                                            readId)

        def dumpData(self,record,out):
            # Truncate or pad the sizes with zeroes as needed
            num_masters = len(record.plugin_masters)
            num_sizes = len(record.master_sizes)
            if num_masters != num_sizes:
                bolt.deprint(
                    u'Masters sizes array mismatch - masters %s, master '
                    u'sizes %s' % (num_masters, num_sizes))
            record.master_sizes = record.master_sizes[:num_masters] + [0] * (
                    num_masters - num_sizes)
            for master_name, master_size in zip(record.plugin_masters,
                                                record.master_sizes):
                self.loaders[b'MAST'].packSub(out, master_name)
                self.loaders[b'DATA'].packSub(out, master_size)

    class MelAuthor(_MelChardet):
        def __init__(self):
            super(MreHeaderBase.MelAuthor, self).__init__(b'CNAM',
                u'author_pstr', ChardetStr(b''), 511)

    class MelDescription(_MelChardet):
        def __init__(self):
            super(MreHeaderBase.MelDescription, self).__init__(b'SNAM',
                u'description_pstr', ChardetStr(b''), 511)

    @property
    def description(self):
        return self.description_pstr._decoded
    @description.setter
    def description(self, new_desc):
        self.description_pstr = _CaseSensitiveStr.from_basestring(new_desc)
    @property
    def author(self):
        return self.author_pstr._decoded
    @author.setter
    def author(self, val):
        self.author_pstr =  _CaseSensitiveStr.from_basestring(val)

    def loadData(self, ins, endPos):
        super(MreHeaderBase, self).loadData(ins, endPos)
        num_masters = self.num_masters
        num_sizes = len(self.master_sizes)
        # Just in case, truncate or pad the sizes with zeroes as needed
        self.master_sizes = self.master_sizes[:num_masters] + [0] * (
                num_masters - num_sizes)

    def getNextObject(self):
        """Gets next object index and increments it for next time."""
        self.nextObject += 1
        self.setChanged()
        return self.nextObject - 1

    @property
    def masters(self):
        return self.plugin_masters

    @masters.setter
    def masters(self, new_masters):
        # TODO below must be per plugin or use bolt.PluginEncoding or... -> note we dump in cp1252
        self.plugin_masters = [
            ChardetStr.from_basestring(x.s if isinstance(x, bolt.Path) else x)
            for x in new_masters]
        # TODO(inf) For Morrowind, this will have to query the files for
        #  their size and then store that
        self.master_sizes = [0 for x in range(len(new_masters))]

    @property
    def num_masters(self): return len(self.plugin_masters)

    __slots__ = []

#------------------------------------------------------------------------------
class MreFlst(MelRecord):
    """FormID List."""
    rec_sig = b'FLST'

    melSet = MelSet(
        MelEdid(),
        MelGroups(u'formIDInList', MelFid(b'LNAM')),
    )

    __slots__ = melSet.getSlotsUsed() + [u'mergeOverLast', u'mergeSources',
                                         u'items', u'de_records',
                                         u're_records']

    def __init__(self, header, ins=None, do_unpack=False):
        super(MreFlst, self).__init__(header, ins, do_unpack)
        self.mergeOverLast = False #--Merge overrides last mod merged
        self.mergeSources = None #--Set to list by other functions
        self.items  = None #--Set of items included in list
        #--Set of items deleted by list (Deflst mods) unused for Skyrim
        self.de_records = None #--Set of items deleted by list (Deflst mods)
        self.re_records = None # unused, needed by patcher

    def mergeFilter(self, modSet):
        if not self.longFids: raise StateError(u'Fids not in long format')
        self.formIDInList = [f for f in self.formIDInList if f[0] in modSet]

    def mergeWith(self,other,otherMod):
        """Merges newLevl settings and entries with self.
        Requires that: self.items, other.de_records be defined."""
        if not self.longFids or not other.longFids:
            raise StateError(u'Fids not in long format')
        #--Remove items based on other.removes
        if other.de_records:
            removeItems = self.items & other.de_records
            self.formIDInList = [fi for fi in self.formIDInList if fi not in removeItems]
            self.items = (self.items | other.de_records)
        #--Add new items from other
        newItems = set()
        formIDInListAppend = self.formIDInList.append
        newItemsAdd = newItems.add
        for fi in other.formIDInList:
            if fi not in self.items:
                formIDInListAppend(fi)
                newItemsAdd(fi)
        if newItems:
            self.items |= newItems
        #--Is merged list different from other? (And thus written to patch.)
        if len(self.formIDInList) != len(other.formIDInList):
            self.mergeOverLast = True
        else:
            for selfEntry,otherEntry in zip(self.formIDInList,other.formIDInList):
                if selfEntry != otherEntry:
                    self.mergeOverLast = True
                    break
            else:
                self.mergeOverLast = False
        if self.mergeOverLast:
            self.mergeSources.append(otherMod)
        else:
            self.mergeSources = [otherMod]
        self.setChanged()

#------------------------------------------------------------------------------
class MreGlob(MelRecord):
    """Global record.  Rather stupidly all values, despite their designation
       (short,long,float), are stored as floats -- which means that very large
       integers lose precision."""
    rec_sig = b'GLOB'

    melSet = MelSet(
        MelEdid(),
        MelFixedString(b'FNAM', u'global_format', default=b's'),
        MelFloat(b'FLTV', u'global_value'),
    )
    __slots__ = melSet.getSlotsUsed()

#------------------------------------------------------------------------------
class MreGmstBase(MelRecord):
    """Game Setting record.  Base class, each game should derive from this
    class."""
    Ids = None
    rec_sig = b'GMST'

    melSet = MelSet(
        MelEdid(),
        MelUnion({
            u'b': MelUInt32(b'DATA', u'value'), # actually a bool
            u'f': MelFloat(b'DATA', u'value'),
            u's': MelLString(b'DATA', u'value'),
        }, decider=AttrValDecider(
            u'eid', transformer=lambda e: e[0] if e else u'i'),
            fallback=MelSInt32(b'DATA', u'value')
        ),
    )
    __slots__ = melSet.getSlotsUsed()

#------------------------------------------------------------------------------
class MreLand(MelRecord):
    """Land structure. Part of exterior cells."""
    rec_sig = b'LAND'

    melSet = MelSet(
        MelBase(b'DATA', u'unknown_land'),
        MelBase(b'VNML', u'vertex_normals'),
        MelBase(b'VHGT', u'vertex_height_map'),
        MelBase(b'VCLR', u'vertex_colors'),
        MelGroups(u'layers',
            # Start a new layer each time we hit one of these
            MelUnion({
                b'ATXT': MelStruct(b'ATXT', u'IBsh', (FID, u'atxt_texture'),
                    u'quadrant', u'unknown', u'layer'),
                b'BTXT': MelStruct(b'BTXT', u'IBsh', (FID, u'btxt_texture'),
                    u'quadrant', u'unknown', u'layer'),
            }),
            # VTXT only exists for ATXT layers, i.e. if ATXT's FormID is valid
            MelUnion({
                True:  MelBase(b'VTXT', u'alpha_layer_data'),
                False: MelNull(b'VTXT'),
            }, decider=FidNotNullDecider(u'atxt_texture')),
        ),
        MelArray(u'vertex_textures',
            MelFid(b'VTEX', u'vertex_texture'),
        ),
    )
    __slots__ = melSet.getSlotsUsed()

#------------------------------------------------------------------------------
class MreLeveledListBase(MelRecord):
    """Base type for leveled item/creature/npc/spells.
       it requires the base class to use the following:
       classAttributes:
          top_copy_attrs -> List of attributes to modify by copying when
                            merging
          entry_copy_attrs -> List of attributes to modify by copying for each
                              list entry when merging
       instanceAttributes:
          entries -> List of items, with the following attributes:
              listId
              level
              count
          chanceNone
          flags
    """
    _flags = bolt.Flags(0,bolt.Flags.getNames(
        (0, 'calcFromAllLevels'),
        (1, 'calcForEachItem'),
        (2, 'useAllSpells'),
        (3, 'specialLoot'),
        ))
    top_copy_attrs = ()
    # TODO(inf) Only overriden for FO3/FNV right now - Skyrim/FO4?
    entry_copy_attrs = ('listId', 'level', 'count')
    __slots__ = ['mergeOverLast', 'mergeSources', 'items', 'de_records',
                 're_records']
                # + ['flags', 'entries'] # define those in the subclasses

    def __init__(self, header, ins=None, do_unpack=False):
        super(MreLeveledListBase, self).__init__(header, ins, do_unpack)
        self.mergeOverLast = False #--Merge overrides last mod merged
        self.mergeSources = None #--Set to list by other functions
        self.items  = None #--Set of items included in list
        self.de_records = None #--Set of items deleted by list (Delev and Relev mods)
        self.re_records = None #--Set of items relevelled by list (Relev mods)

    def mergeFilter(self,modSet):
        if not self.longFids: raise StateError(u'Fids not in long format')
        self.entries = [entry for entry in self.entries if entry.listId[0] in modSet]

    def mergeWith(self,other,otherMod):
        """Merges newLevl settings and entries with self.
        Requires that self.items, other.de_records and other.re_records be
        defined."""
        if not self.longFids or not other.longFids:
            raise exception.StateError(u'Fids not in long format')
        #--Relevel or not?
        if other.re_records:
            for attr in self.__class__.top_copy_attrs:
                setattr(self, attr, getattr(other, attr))
            self.flags = other.flags()
        else:
            for attr in self.__class__.top_copy_attrs:
                otherAttr = getattr(other, attr)
                if otherAttr is not None:
                    setattr(self, attr, otherAttr)
            self.flags |= other.flags
        #--Remove items based on other.removes
        if other.de_records or other.re_records:
            removeItems = self.items & (other.de_records | other.re_records)
            self.entries = [entry for entry in self.entries if entry.listId not in removeItems]
            self.items = (self.items | other.de_records) - other.re_records
        hasOldItems = bool(self.items)
        #--Add new items from other
        newItems = set()
        entriesAppend = self.entries.append
        newItemsAdd = newItems.add
        for entry in other.entries:
            if entry.listId not in self.items:
                entriesAppend(entry)
                newItemsAdd(entry.listId)
        # Check if merging exceeded the counter's limit and, if so, truncate it
        # and warn. Note that pre-Skyrim games do not have this limitation.
        from .. import bush
        max_lvl_size = bush.game.Esp.max_lvl_list_size
        if max_lvl_size and len(self.entries) > max_lvl_size:
            # TODO(inf) In the future, offer an option to auto-split these into
            #  multiple sub-lists instead
            bolt.deprint(u"Merging changes from mod '%s' to leveled list %r "
                         u'caused it to exceed %u entries. Truncating back '
                         u'to %u, you will have to fix this manually!' %
                         (otherMod, self, max_lvl_size, max_lvl_size))
            self.entries = self.entries[:max_lvl_size]
        entry_copy_attrs_key = attrgetter(*self.__class__.entry_copy_attrs)
        if newItems:
            self.items |= newItems
            self.entries.sort(key=entry_copy_attrs_key)
        #--Is merged list different from other? (And thus written to patch.)
        if ((len(self.entries) != len(other.entries)) or
                (self.flags != other.flags)):
            self.mergeOverLast = True
        else:
            # Check copy-attributes first, break if they are different
            for attr in self.__class__.top_copy_attrs:
                if getattr(self, attr) != getattr(other, attr):
                    self.mergeOverLast = True
                    break
            else:
                # Then, check the sort-attributes, same story
                otherlist = other.entries
                otherlist.sort(key=entry_copy_attrs_key)
                for selfEntry,otherEntry in zip(self.entries,otherlist):
                    for attr in self.__class__.entry_copy_attrs:
                        if getattr(selfEntry, attr) != getattr(
                                otherEntry, attr):
                            break
                    else:
                        # attributes are identical, try next entry
                        continue
                    # attributes differ, no need to look at more entries
                    self.mergeOverLast = True
                    break
                else:
                    # Neither one had different attributes
                    self.mergeOverLast = False
        if self.mergeOverLast:
            self.mergeSources.append(otherMod)
        else:
            self.mergeSources = [otherMod]
        self.setChanged(self.mergeOverLast)

#------------------------------------------------------------------------------
class MreWithItems(MelRecord):
    """Base class for record types that contain a list of items (MelItems)."""
    __slots__ = []

    def mergeFilter(self, modSet):
        if not self.longFids: raise StateError(u'Fids not in long format')
        self.items = [i for i in self.items if i.item[0] in modSet]

#------------------------------------------------------------------------------
class MreActorBase(MreWithItems):
    """Base class for Creatures and NPCs."""
    __slots__ = []

    def mergeFilter(self, modSet):
        super(MreActorBase, self).mergeFilter(modSet)
        self.spells = [x for x in self.spells if x[0] in modSet]
        self.factions = [x for x in self.factions if x.faction[0] in modSet]

#------------------------------------------------------------------------------
class MelModelCompare(MelGroup):

    class _CompareModPaths(AttrsCompare):
        compare_attrs = frozenset([u'modPath'])
        __slots__ = ()
    _mel_object_base_type = _CompareModPaths
