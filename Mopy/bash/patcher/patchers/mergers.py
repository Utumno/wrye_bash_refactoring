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
"""This module houses mergers. A merger is an import patcher that targets a
list of entries, adding, removing (and, for more complex entries, changing)
entries from multiple tagged plugins to create a final merged list. The goal is
to eventually absorb all of them under the _AMerger base class."""
import copy
from collections import defaultdict, Counter
from itertools import chain
from operator import attrgetter
# Internal
from .base import ImportPatcher, ListPatcher
from ... import bush
from ...bolt import GPath
from ...brec import MreRecord
from ...exception import AbstractError, ModSigMismatchError
from ...mod_files import ModFile, LoadFactory

#------------------------------------------------------------------------------
##: currently relies on the merged subrecord being sorted - fix that
##: add ForceAdd support
##: once the two tasks above are done, absorb all other mergers
##: a lot of code still shared with _APreserver - move to ImportPatcher
class _AMerger(ImportPatcher):
    """Still very WIP base class for mergers."""
    # Bash tags for each function of the merger. None means that it does not
    # support that function. E.g. the change tag is only applicable if the
    # entries in question are more complex than mere FormIDs.
    _add_tag = None
    _change_tag = None
    _remove_tag = None
    # Dict mapping each record type to the subrecord we want to merge for it
    _wanted_subrecord = {}

    def __init__(self, p_name, p_file, p_sources):
        ##: Is this equivalent to allowUnloaded on the CBash side?
        p_sources = [x for x in p_sources if
                     x in p_file.p_file_minfos and x in p_file.allSet]
        super(_AMerger, self).__init__(p_name, p_file, p_sources)
        self.id_deltas = defaultdict(list)
        self.masters = set(chain.from_iterable(
            self._recurse_masters(srcMod, p_file.p_file_minfos)
            for srcMod in self.srcs))
        self._masters_and_srcs = self.masters | set(self.srcs)
        # Set of record signatures that are actually provided by sources
        self._present_sigs = set()
        self.mod_id_entries = {}
        self.touched = set()
        self.inventOnlyMods = (
            {x for x in self.srcs if x in p_file.mergeSet and u'IIM' in
             p_file.p_file_minfos[x].getBashTags()} if self.iiMode else set())

    ##: Move to ModInfo? get_recursive_masters()?
    def _recurse_masters(self, srcMod, minfs):
        """Recursively collects all masters of srcMod."""
        ret_masters = set()
        src_masters = minfs[srcMod].masterNames if srcMod in minfs else []
        for src_master in src_masters:
            ret_masters.add(src_master)
            ret_masters.update(self._recurse_masters(src_master, minfs))
        return ret_masters

    ##: post-tweak pooling, see if we can use RecPath for this
    def _entry_key(self, subrecord_entry):
        """Returns a key to sort and compare by for the specified subrecord
        entry. Default implementation returns the entry itself (useful if the
        subrecord is e.g. just a list of FormIDs)."""
        return subrecord_entry

    def getReadClasses(self):
        return tuple(self._present_sigs) if self.isActive else ()

    def getWriteClasses(self):
        return self.getReadClasses()

    def initData(self,progress):
        if not self.isActive or not self.srcs: return
        wanted_sigs = list(self._wanted_subrecord)
        loadFactory = LoadFactory(False, *[MreRecord.type_class[x]
                                           for x in wanted_sigs])
        progress.setFull(len(self.srcs))
        for index,srcMod in enumerate(self.srcs):
            srcInfo = self.patchFile.p_file_minfos[srcMod]
            srcFile = ModFile(srcInfo,loadFactory)
            srcFile.load(True)
            for block in wanted_sigs:
                if block not in srcFile.tops: continue
                self._present_sigs.add(block)
                for record in srcFile.tops[block].getActiveRecords():
                    self.touched.add(record.fid)
            progress.plus()
        self.isActive = bool(self._present_sigs)

    def scanModFile(self, modFile, progress):
        if not self.isActive: return
        touched = self.touched
        id_deltas = self.id_deltas
        mod_id_entries = self.mod_id_entries
        modName = modFile.fileInfo.name
        #--Master or source?
        if modName in self._masters_and_srcs:
            id_entries = mod_id_entries[modName] = {}
            for curr_sig in self._present_sigs:
                if curr_sig not in modFile.tops: continue
                sr_attr = self._wanted_subrecord[curr_sig]
                for record in modFile.tops[curr_sig].getActiveRecords():
                    if record.fid in touched:
                        try:
                            id_entries[record.fid] = getattr(
                                record, sr_attr)[:]
                        except AttributeError:
                            raise ModSigMismatchError(modName, record)
        #--Source mod?
        if modName in self.srcs:
            # The applied tags limit what data we're going to collect
            applied_tags = modFile.fileInfo.getBashTags()
            can_add = self._add_tag in applied_tags
            can_change = self._change_tag in applied_tags
            can_remove = self._remove_tag in applied_tags
            id_entries = {}
            en_key = self._entry_key
            for master in modFile.tes4.masters:
                if master in mod_id_entries:
                    id_entries.update(mod_id_entries[master])
            for fid,entries in mod_id_entries[modName].iteritems():
                masterEntries = id_entries.get(fid)
                if masterEntries is None: continue
                master_keys = {en_key(x) for x in masterEntries}
                mod_keys = {en_key(x) for x in entries}
                remove_keys = master_keys - mod_keys if can_remove else set()
                # Note that we need to calculate these whether or not we're
                # Add-tagged, because Change needs them as well.
                addItems = mod_keys - master_keys
                addEntries = [x for x in entries if en_key(x) in addItems]
                # Changed entries are those entries that haven't been newly
                # added but also differ from the master entries
                if can_change:
                    lookup_added = set(addEntries)
                    lookup_masters = set(masterEntries)
                    changed_entries = [x for x in entries
                                       if x not in lookup_masters
                                       and x not in lookup_added]
                else:
                    changed_entries = []
                final_add_entries = addEntries if can_add else []
                if remove_keys or final_add_entries or changed_entries:
                    id_deltas[fid].append((remove_keys, final_add_entries,
                                           changed_entries))
        # Copy the new records we want to keep, unless we're an IIM merger and
        # the mod is IIM-tagged
        if modFile.fileInfo.name not in self.inventOnlyMods:
            for curr_sig in self._present_sigs:
                curr_sig = unicode(curr_sig, u'ascii')
                patchBlock = getattr(self.patchFile, curr_sig)
                id_records = patchBlock.id_records
                for record in getattr(modFile, curr_sig).getActiveRecords():
                    # Copy the defining version of each record into the BP -
                    # updating it is handled by
                    # mergeModFile/update_patch_records_from_mod
                    curr_fid = record.fid
                    if curr_fid in touched and curr_fid not in id_records:
                        patchBlock.setRecord(record.getTypeCopy())

    def buildPatch(self,log,progress):
        if not self.isActive: return
        keep = self.patchFile.getKeeper()
        id_deltas = self.id_deltas
        mod_count = Counter()
        en_key = self._entry_key
        for curr_sig in self._present_sigs:
            sr_attr = self._wanted_subrecord[curr_sig]
            for record in getattr(self.patchFile, unicode(
                    curr_sig, u'ascii')).records:
                deltas = id_deltas[record.fid]
                if not deltas: continue
                # Use sorted to preserve duplicates, but ignore order. This is
                # safe because order does not matter for items.
                old_items = sorted(getattr(record, sr_attr), key=en_key)
                for remove_keys, add_entries, change_entries in deltas:
                    # First execute removals, don't want to change something
                    # we're going to remove
                    if remove_keys:
                        setattr(record, sr_attr,
                            [x for x in getattr(record, sr_attr)
                             if en_key(x) not in remove_keys])
                    # Then execute changes, don't want to modify our own
                    # additions
                    if change_entries:
                        # In order to not modify the list while iterating
                        final_remove = set()
                        final_add = []
                        record_entries = getattr(record, sr_attr)
                        for change_entry in change_entries:
                            # Look for one with the same item - can't just use
                            # a dict or change the items directly because we
                            # have to respect duplicates
                            for curr_entry in record_entries:
                                if en_key(change_entry) == en_key(curr_entry):
                                    # Remove the old entry, add the changed one
                                    final_remove.add(curr_entry)
                                    final_add.append(change_entry)
                                    break
                        # No need to check both, see add/append above
                        if final_remove:
                            setattr(record, sr_attr,
                                [x for x in record_entries
                                 if x not in final_remove] + final_add)
                    # Finally, execute additions - fairly straightforward
                    if add_entries:
                        record_entries = getattr(record, sr_attr)
                        current_entries = {en_key(x) for x in record_entries}
                        for entry in add_entries:
                            if en_key(entry) not in current_entries:
                                record_entries.append(entry)
                if old_items != sorted(getattr(record, sr_attr), key=en_key):
                    keep(record.fid)
                    mod_count[record.fid[0]] += 1
        self.id_deltas.clear()
        self._patchLog(log,mod_count)

    def _plog(self, log, mod_count): self._plog1(log, mod_count)

#------------------------------------------------------------------------------
# Absorbed patchers -----------------------------------------------------------
#------------------------------------------------------------------------------
class ImportInventory(_AMerger):
    logMsg = u'\n=== ' + _(u'Inventories Changed') + u': %d'
    _add_tag = u'Invent.Add'
    _change_tag = u'Invent.Change'
    _remove_tag = u'Invent.Remove'
    _wanted_subrecord = {x: u'items' for x in bush.game.inventoryTypes}
    iiMode = True

    def _entry_key(self, subrecord_entry):
        return subrecord_entry.item

#------------------------------------------------------------------------------
class ImportOutfits(_AMerger):
    logMsg = u'\n=== ' + _(u'Outfits Changed') + u': %d'
    _add_tag = u'Outfits.Add'
    _remove_tag = u'Outfits.Remove'
    _wanted_subrecord = {b'OTFT': u'items'}

#------------------------------------------------------------------------------
class ImportRelations(_AMerger):
    logMsg = u'\n=== ' + _(u'Modified Factions') + u': %d'
    _add_tag = u'Relations.Add'
    _change_tag = u'Relations.Change'
    _remove_tag = u'Relations.Remove'
    _wanted_subrecord = {b'FACT': u'relations'}

    def _entry_key(self, subrecord_entry):
        return subrecord_entry.faction

#------------------------------------------------------------------------------
# Patchers to absorb ----------------------------------------------------------
#------------------------------------------------------------------------------
class ImportActorsSpells(ImportPatcher):
    logMsg = u'\n=== ' + _(u'Spell Lists Changed') + u': %d'

    def __init__(self, p_name, p_file, p_sources):
        super(ImportActorsSpells, self).__init__(p_name, p_file, p_sources)
        # long_fid -> {'merged':list[long_fid], 'deleted':list[long_fid]}
        self.id_merged_deleted = {}
        self._read_write_records = bush.game.actor_types

    def initData(self,progress):
        """Get data from source files."""
        if not self.isActive: return
        target_rec_types = self._read_write_records
        loadFactory = LoadFactory(False, *[MreRecord.type_class[x] for x
                                           in target_rec_types])
        progress.setFull(len(self.srcs))
        cachedMasters = {}
        mer_del = self.id_merged_deleted
        minfs = self.patchFile.p_file_minfos
        for index,srcMod in enumerate(self.srcs):
            tempData = {}
            if srcMod not in minfs: continue
            srcInfo = minfs[srcMod]
            srcFile = ModFile(srcInfo,loadFactory)
            bashTags = srcInfo.getBashTags()
            srcFile.load(True)
            for recClass in (MreRecord.type_class[x] for x in target_rec_types):
                if recClass.rec_sig not in srcFile.tops: continue
                for record in srcFile.tops[recClass.rec_sig].getActiveRecords():
                    tempData[record.fid] = record.spells
            for master in reversed(srcInfo.masterNames):
                if master not in minfs: continue # or break filter mods
                if master in cachedMasters:
                    masterFile = cachedMasters[master]
                else:
                    masterInfo = minfs[master]
                    masterFile = ModFile(masterInfo,loadFactory)
                    masterFile.load(True)
                    cachedMasters[master] = masterFile
                for block in (MreRecord.type_class[x] for x in target_rec_types):
                    if block.rec_sig not in srcFile.tops: continue
                    if block.rec_sig not in masterFile.tops: continue
                    for record in masterFile.tops[block.rec_sig].getActiveRecords():
                        fid = record.fid
                        if fid not in tempData: continue
                        if record.spells == tempData[fid] and not u'Actors.SpellsForceAdd' in bashTags:
                            # if subrecord is identical to the last master then we don't care about older masters.
                            del tempData[fid]
                            continue
                        if fid in mer_del:
                            if tempData[fid] == mer_del[fid]['merged']: continue
                        recordData = {'deleted':[],'merged':tempData[fid]}
                        for spell in record.spells:
                            if spell not in tempData[fid]:
                                recordData['deleted'].append(spell)
                        if fid not in mer_del:
                            mer_del[fid] = recordData
                        else:
                            for spell in recordData['deleted']:
                                if spell in mer_del[fid]['merged']:
                                    mer_del[fid]['merged'].remove(spell)
                                mer_del[fid]['deleted'].append(spell)
                            if mer_del[fid]['merged'] == []:
                                for spell in recordData['merged']:
                                    if spell in mer_del[fid]['deleted'] and not u'Actors.SpellsForceAdd' in bashTags: continue
                                    mer_del[fid]['merged'].append(spell)
                                continue
                            for index, spell in enumerate(recordData['merged']):
                                if spell not in mer_del[fid]['merged']: # so needs to be added... (unless deleted that is)
                                    # find the correct position to add and add.
                                    if spell in mer_del[fid]['deleted'] and not u'Actors.SpellsForceAdd' in bashTags: continue #previously deleted
                                    if index == 0:
                                        mer_del[fid]['merged'].insert(0, spell) #insert as first item
                                    elif index == (len(recordData['merged'])-1):
                                        mer_del[fid]['merged'].append(spell) #insert as last item
                                    else: #figure out a good spot to insert it based on next or last recognized item (ugly ugly ugly)
                                        i = index - 1
                                        while i >= 0:
                                            if recordData['merged'][i] in mer_del[fid]['merged']:
                                                slot = mer_del[fid]['merged'].index(recordData['merged'][i]) + 1
                                                mer_del[fid]['merged'].insert(slot, spell)
                                                break
                                            i -= 1
                                        else:
                                            i = index + 1
                                            while i != len(recordData['merged']):
                                                if recordData['merged'][i] in mer_del[fid]['merged']:
                                                    slot = mer_del[fid]['merged'].index(recordData['merged'][i])
                                                    mer_del[fid]['merged'].insert(slot, spell)
                                                    break
                                                i += 1
                                    continue # Done with this package
                                elif index == mer_del[fid]['merged'].index(spell) or (len(recordData['merged'])-index) == (len(mer_del[fid]['merged'])-mer_del[fid]['merged'].index(spell)): continue #spell same in both lists.
                                else: #this import is later loading so we'll assume it is better order
                                    mer_del[fid]['merged'].remove(spell)
                                    if index == 0:
                                        mer_del[fid]['merged'].insert(0, spell) #insert as first item
                                    elif index == (len(recordData['merged'])-1):
                                        mer_del[fid]['merged'].append(spell) #insert as last item
                                    else:
                                        i = index - 1
                                        while i >= 0:
                                            if recordData['merged'][i] in mer_del[fid]['merged']:
                                                slot = mer_del[fid]['merged'].index(recordData['merged'][i]) + 1
                                                mer_del[fid]['merged'].insert(slot, spell)
                                                break
                                            i -= 1
                                        else:
                                            i = index + 1
                                            while i != len(recordData['merged']):
                                                if recordData['merged'][i] in mer_del[fid]['merged']:
                                                    slot = mer_del[fid]['merged'].index(recordData['merged'][i])
                                                    mer_del[fid]['merged'].insert(slot, spell)
                                                    break
                                                i += 1
            progress.plus()

    def scanModFile(self, modFile, progress): # scanModFile2
        """Add record from modFile."""
        merged_deleted = self.id_merged_deleted
        for type in self._read_write_records:
            patchBlock = getattr(self.patchFile,type)
            for record in getattr(modFile,type).getActiveRecords():
                fid = record.fid
                if fid in merged_deleted:
                    if record.spells != merged_deleted[fid]['merged']:
                        patchBlock.setRecord(record.getTypeCopy())

    def buildPatch(self,log,progress): # buildPatch1:no modFileTops, for type..
        """Applies delta to patchfile."""
        if not self.isActive: return
        keep = self.patchFile.getKeeper()
        merged_deleted = self.id_merged_deleted
        mod_count = Counter()
        for rec_type in self._read_write_records:
            for record in getattr(self.patchFile,rec_type).records:
                fid = record.fid
                if fid not in merged_deleted: continue
                changed = False
                mergedSpells = sorted(merged_deleted[fid]['merged'])
                if sorted(record.spells) != mergedSpells:
                    record.spells = mergedSpells
                    changed = True
                if changed:
                    keep(record.fid)
                    mod_count[record.fid[0]] += 1
        self.id_merged_deleted.clear()
        self._patchLog(log,mod_count)

    def _plog(self, log, mod_count): self._plog1(log, mod_count)

#------------------------------------------------------------------------------
class NPCAIPackagePatcher(ImportPatcher):
    logMsg = u'\n=== ' + _(u'AI Package Lists Changed') + u': %d'

    def __init__(self, p_name, p_file, p_sources):
        super(NPCAIPackagePatcher, self).__init__(p_name, p_file, p_sources)
        # long_fid -> {'merged':list[long_fid], 'deleted':list[long_fid]}
        self.id_merged_deleted = {}
        self.target_rec_types = bush.game.actor_types

    def _insertPackage(self, id_merged_deleted, fi, index, pkg, recordData):
        fi_merged = id_merged_deleted[fi]['merged']
        if index == 0: fi_merged.insert(0, pkg)# insert as first item
        elif index == (len(recordData['merged']) - 1):
            fi_merged.append(pkg)  # insert as last item
        else:  # figure out a good spot to insert it based on next or last
            # recognized item (ugly ugly ugly)
            i = index - 1
            while i >= 0:
                if recordData['merged'][i] in fi_merged:
                    slot = fi_merged.index(
                        recordData['merged'][i]) + 1
                    fi_merged.insert(slot, pkg)
                    break
                i -= 1
            else:
                i = index + 1
                while i != len(recordData['merged']):
                    if recordData['merged'][i] in fi_merged:
                        slot = fi_merged.index(
                            recordData['merged'][i])
                        fi_merged.insert(slot, pkg)
                        break
                    i += 1

    def initData(self,progress):
        """Get data from source files."""
        if not self.isActive: return
        target_rec_types = self.target_rec_types
        loadFactory = LoadFactory(False, *[MreRecord.type_class[x] for x
                                           in target_rec_types])
        progress.setFull(len(self.srcs))
        cachedMasters = {}
        mer_del = self.id_merged_deleted
        minfs = self.patchFile.p_file_minfos
        for index,srcMod in enumerate(self.srcs):
            tempData = {}
            if srcMod not in minfs: continue
            srcInfo = minfs[srcMod]
            srcFile = ModFile(srcInfo,loadFactory)
            bashTags = srcInfo.getBashTags()
            srcFile.load(True)
            for recClass in (MreRecord.type_class[x] for x in target_rec_types):
                if recClass.rec_sig not in srcFile.tops: continue
                for record in srcFile.tops[
                    recClass.rec_sig].getActiveRecords():
                    tempData[record.fid] = record.aiPackages
            for master in reversed(srcInfo.masterNames):
                if master not in minfs: continue # or break filter mods
                if master in cachedMasters:
                    masterFile = cachedMasters[master]
                else:
                    masterInfo = minfs[master]
                    masterFile = ModFile(masterInfo,loadFactory)
                    masterFile.load(True)
                    cachedMasters[master] = masterFile
                blocks = (MreRecord.type_class[x] for x in target_rec_types)
                for block in blocks:
                    if block.rec_sig not in srcFile.tops: continue
                    if block.rec_sig not in masterFile.tops: continue
                    for record in masterFile.tops[
                        block.rec_sig].getActiveRecords():
                        fi = record.fid
                        if fi not in tempData: continue
                        if record.aiPackages == tempData[fi] and not \
                            u'Actors.AIPackagesForceAdd' in bashTags:
                            # if subrecord is identical to the last master
                            # then we don't care about older masters.
                            del tempData[fi]
                            continue
                        if fi in mer_del:
                            if tempData[fi] == mer_del[fi]['merged']:
                                continue
                        recordData = {'deleted':[],'merged':tempData[fi]}
                        for pkg in record.aiPackages:
                            if pkg not in tempData[fi]:
                                recordData['deleted'].append(pkg)
                        if fi not in mer_del:
                            mer_del[fi] = recordData
                        else:
                            for pkg in recordData['deleted']:
                                if pkg in mer_del[fi]['merged']:
                                    mer_del[fi]['merged'].remove(pkg)
                                mer_del[fi]['deleted'].append(pkg)
                            if mer_del[fi]['merged'] == []:
                                for pkg in recordData['merged']:
                                    if pkg in mer_del[fi]['deleted'] and not \
                                      u'Actors.AIPackagesForceAdd' in bashTags:
                                        continue
                                    mer_del[fi]['merged'].append(pkg)
                                continue
                            for index, pkg in enumerate(recordData['merged']):
                                if pkg not in mer_del[fi]['merged']:# so needs
                                    #  to be added... (unless deleted that is)
                                    # find the correct position to add and add.
                                    if pkg in mer_del[fi]['deleted'] and not \
                                      u'Actors.AIPackagesForceAdd' in bashTags:
                                        continue  # previously deleted
                                    self._insertPackage(mer_del, fi, index,
                                                        pkg, recordData)
                                    continue # Done with this package
                                elif index == mer_del[fi]['merged'].index(
                                        pkg) or (
                                    len(recordData['merged']) - index) == (
                                    len(mer_del[fi]['merged']) - mer_del[fi][
                                    'merged'].index(pkg)):
                                    continue  # pkg same in both lists.
                                else:  # this import is later loading so we'll
                                    #  assume it is better order
                                    mer_del[fi]['merged'].remove(pkg)
                                    self._insertPackage(mer_del, fi, index,
                                                        pkg, recordData)
            progress.plus()

    def getReadClasses(self):
        """Returns load factory classes needed for reading."""
        return bush.game.actor_types if self.isActive else ()

    def getWriteClasses(self):
        """Returns load factory classes needed for writing."""
        return bush.game.actor_types if self.isActive else ()

    def scanModFile(self, modFile, progress): # scanModFile2: loop, LongTypes..
        """Add record from modFile."""
        merged_deleted = self.id_merged_deleted
        for rec_type in self.target_rec_types:
            patchBlock = getattr(self.patchFile,rec_type)
            for record in getattr(modFile,rec_type).getActiveRecords():
                fid = record.fid
                if fid not in merged_deleted: continue
                if record.aiPackages != merged_deleted[fid]['merged']:
                    patchBlock.setRecord(record.getTypeCopy())

    def buildPatch(self,log,progress): # buildPatch1:no modFileTops, for type..
        """Applies delta to patchfile."""
        if not self.isActive: return
        keep = self.patchFile.getKeeper()
        merged_deleted = self.id_merged_deleted
        mod_count = Counter()
        for rec_type in self.target_rec_types:
            for record in getattr(self.patchFile,rec_type).records:
                fid = record.fid
                if fid not in merged_deleted: continue
                changed = False
                if record.aiPackages != merged_deleted[fid]['merged']:
                    record.aiPackages = merged_deleted[fid]['merged']
                    changed = True
                if changed:
                    keep(record.fid)
                    mod_count[record.fid[0]] += 1
        self.id_merged_deleted.clear()
        self._patchLog(log,mod_count)

    def _plog(self, log, mod_count): self._plog1(log, mod_count)

#------------------------------------------------------------------------------
class _AListsMerger(ListPatcher):
    """Merges lists of objects, e.g. leveled lists or FormID lists."""
    group = _(u'Special')
    scanOrder = 45
    editOrder = 45
    iiMode = True
    # De/Re Tags - None means the patcher does not have such a tag
    _de_tag = None
    _re_tag = None
    # Maps record type (str) to translated label (unicode)
    _type_to_label = {}
    _de_re_header = None

    def _overhaul_compat(self, mods, _skip_id):
        OOOMods = {GPath(u"Oscuro's_Oblivion_Overhaul.esm"),
                   GPath(u"Oscuro's_Oblivion_Overhaul.esp")}
        FransMods = {GPath(u"Francesco's Leveled Creatures-Items Mod.esm"),
                     GPath(u"Francesco.esp")}
        WCMods = {GPath(u"Oblivion Warcry.esp"),
                  GPath(u"Oblivion Warcry EV.esp")}
        TIEMods = {GPath(u"TIE.esp")}
        OverhaulCompat = GPath(u"Unofficial Oblivion Patch.esp") in mods and (
                (OOOMods | WCMods) & mods) or (
                                 FransMods & mods and not (TIEMods & mods))
        if OverhaulCompat:
            self.OverhaulUOPSkips = set(
                [_skip_id(x) for x in [
                    0x03AB5D,  # VendorWeaponBlunt
                    0x03C7F1,  # LL0LootWeapon0Magic4Dwarven100
                    0x03C7F2,  # LL0LootWeapon0Magic7Ebony100
                    0x03C7F3,  # LL0LootWeapon0Magic5Elven100
                    0x03C7F4,  # LL0LootWeapon0Magic6Glass100
                    0x03C7F5,  # LL0LootWeapon0Magic3Silver100
                    0x03C7F7,  # LL0LootWeapon0Magic2Steel100
                    0x03E4D2,  # LL0NPCWeapon0MagicClaymore100
                    0x03E4D3,  # LL0NPCWeapon0MagicClaymoreLvl100
                    0x03E4DA,  # LL0NPCWeapon0MagicWaraxe100
                    0x03E4DB,  # LL0NPCWeapon0MagicWaraxeLvl100
                    0x03E4DC,  # LL0NPCWeapon0MagicWarhammer100
                    0x03E4DD,  # LL0NPCWeapon0MagicWarhammerLvl100
                    0x0733EA,  # ArenaLeveledHeavyShield,
                    0x0C7615,  # FGNPCWeapon0MagicClaymoreLvl100
                    0x181C66,  # SQ02LL0NPCWeapon0MagicClaymoreLvl100
                    0x053877,  # LL0NPCArmor0MagicLightGauntlets100
                    0x053878,  # LL0NPCArmor0MagicLightBoots100
                    0x05387A,  # LL0NPCArmor0MagicLightCuirass100
                    0x053892,  # LL0NPCArmor0MagicLightBootsLvl100
                    0x053893,  # LL0NPCArmor0MagicLightCuirassLvl100
                    0x053894,  # LL0NPCArmor0MagicLightGauntletsLvl100
                    0x053D82,  # LL0LootArmor0MagicLight5Elven100
                    0x053D83,  # LL0LootArmor0MagicLight6Glass100
                    0x052D89,  # LL0LootArmor0MagicLight4Mithril100
                ]])
        else:
            self.OverhaulUOPSkips = set()

    def __init__(self, p_name, p_file, p_sources, remove_empty, tag_choices):
        """In addition to default parameters, accepts a boolean remove_empty,
        which determines whether or not the 'empty sublist removal' logic
        should run, and a defaultdict tag_choices, which maps each tagged
        plugin (represented as paths) to a set of the applied tags (as unicode
        strings, e.g. u'Delev'), defaulting to an empty set.

        :type remove_empty: bool
        :type tag_choices: defaultdict[bolt.Path, set[unicode]]"""
        super(_AListsMerger, self).__init__(p_name, p_file, p_sources)
        self.isActive |= bool(p_file.loadSet) # Can do meaningful work even without sources
        self.type_list = dict([(rec, {}) for rec in self._read_write_records])
        self.masterItems = defaultdict(dict)
        # Calculate levelers/de_masters first, using unmodified self.srcs
        self.levelers = [leveler for leveler in self.srcs if
                         leveler in self.patchFile.allSet]
        # de_masters is a set of all the masters of each leveler, i.e. each
        # tagged plugin. These are the masters we have to consider records from
        # when determining whether or not to carry forward removals done by a
        # 'De'-tagged plugin
        self.de_masters = set()
        for leveler in self.levelers:
            self.de_masters.update(p_file.p_file_minfos[leveler].masterNames)
        self.srcs = set(self.srcs) & p_file.loadSet
        self.remove_empty_sublists = remove_empty
        self.tag_choices = tag_choices

    def annotate_plugin(self, ann_plugin):
        """Returns the name of the specified plugin, with any Relev/Delev tags
        appended as [ADR], similar to how the patcher GUI displays it.

        :param ann_plugin: The plugin to return the name for, as a path.
        :type ann_plugin: bolt.Path"""
        applied_tags = [t[0] for t in self.tag_choices[ann_plugin]]
        return ann_plugin.s + (u' [%s]' % u''.join(sorted(applied_tags))
                               if applied_tags else u'')

    def scanModFile(self, modFile, progress):
        #--Begin regular scan
        sc_name = modFile.fileInfo.name
        #--PreScan for later Relevs/Delevs?
        if sc_name in self.de_masters:
            for list_type in self._read_write_records:
                for de_list in getattr(modFile, list_type).getActiveRecords():
                    self.masterItems[de_list.fid][sc_name] = set(
                        self._get_entries(de_list))
        #--Relev/Delev setup
        applied_tags = self.tag_choices[sc_name]
        is_relev = self._re_tag in applied_tags
        is_delev = self._de_tag in applied_tags
        #--Scan
        for list_type in self._read_write_records:
            stored_lists = self.type_list[list_type]
            new_lists = getattr(modFile, list_type)
            for new_list in new_lists.getActiveRecords():
                list_fid = new_list.fid
                # FIXME(inf) This is hideous and slows everything down
                if (sc_name == u'Unofficial Oblivion Patch.esp' and
                        list_fid in self.OverhaulUOPSkips):
                    stored_lists[list_fid].mergeOverLast = True
                    continue
                is_list_owner = (list_fid[0] == sc_name)
                #--Items, delevs and relevs sets
                new_list.items = items = set(self._get_entries(new_list))
                if not is_list_owner:
                    #--Relevs
                    new_list.re_records = items.copy() if is_relev else set()
                    #--Delevs: all items in masters minus current items
                    new_list.de_records = delevs = set()
                    if is_delev:
                        id_master_items = self.masterItems.get(list_fid)
                        if id_master_items:
                            for de_master in modFile.tes4.masters:
                                if de_master in id_master_items:
                                    delevs |= id_master_items[de_master]
                            # TODO(inf) Double-check that this works correctly,
                            #  this line (delevs -= items) seems a noop here
                            delevs -= items
                            new_list.items |= delevs
                #--Cache/Merge
                if is_list_owner:
                    de_list = copy.deepcopy(new_list)
                    de_list.mergeSources = []
                    stored_lists[list_fid] = de_list
                elif list_fid not in stored_lists:
                    de_list = copy.deepcopy(new_list)
                    de_list.mergeSources = [sc_name]
                    stored_lists[list_fid] = de_list
                else:
                    stored_lists[list_fid].mergeWith(new_list, sc_name)

    def buildPatch(self, log, progress):
        keep = self.patchFile.getKeeper()
        # Relevs/Delevs List
        log.setHeader(u'= ' + self._patcher_name, True)
        log.setHeader(u'=== ' + self._de_re_header)
        for leveler in self.levelers:
            log(u'* ' + self.annotate_plugin(leveler))
        # Save to patch file
        for list_type, list_label in self._type_to_label.iteritems():
            if list_type not in self._read_write_records: continue
            log.setHeader(u'=== ' + _(u'Merged %s Lists') % list_label)
            patch_block = getattr(self.patchFile, list_type)
            stored_lists = self.type_list[list_type]
            for stored_list in sorted(stored_lists.values(),
                                      key=attrgetter('eid')):
                if not stored_list.mergeOverLast: continue
                list_fid = stored_list.fid
                keep(list_fid)
                patch_block.setRecord(stored_lists[list_fid])
                log(u'* ' + stored_list.eid)
                for merge_source in stored_list.mergeSources:
                    log(u'  * ' + self.annotate_plugin(merge_source))
                self._check_list(stored_list, log)
        #--Discard empty sublists
        if not self.remove_empty_sublists: return
        for list_type, list_label in self._type_to_label.iteritems():
            if list_type not in self._read_write_records: continue
            patch_block = getattr(self.patchFile, list_type)
            stored_lists = self.type_list[list_type]
            empty_lists = []
            # Build a dict mapping leveled lists to other leveled lists that
            # they are sublists in
            sub_supers = dict((x, []) for x in stored_lists.keys())
            for stored_list in sorted(stored_lists.values()):
                list_fid = stored_list.fid
                if not stored_list.items:
                    empty_lists.append(list_fid)
                else:
                    sub_lists = [x for x in stored_list.items
                                if x in sub_supers]
                    for sub_list in sub_lists:
                        sub_supers[sub_list].append(list_fid)
            #--Clear empties
            removed_empty_sublists = set()
            cleaned_lists = set()
            while empty_lists:
                empty_list = empty_lists.pop()
                if empty_list not in sub_supers: continue
                # We have an empty list, look if it's a sublist in any other
                # list
                for sub_super in sub_supers[empty_list]:
                    stored_list = stored_lists[sub_super]
                    # Remove the emtpy list from this sublist
                    old_entries = stored_list.entries
                    stored_list.entries = [x for x in stored_list.entries
                                           if x.listId != empty_list]
                    stored_list.items.remove(empty_list)
                    patch_block.setRecord(stored_list)
                    # If removing the empty list made this list empty too, then
                    # we should investigate it as well - could clean up even
                    # more lists
                    if not stored_list.items:
                        empty_lists.append(sub_super)
                    removed_empty_sublists.add(stored_lists[empty_list].eid)
                    # We don't need to write out records where another mod has
                    # already removed the empty sublist - that would just make
                    # an ITPO
                    if old_entries != stored_list.entries:
                        cleaned_lists.add(stored_list.eid)
                        keep(sub_super)
            log.setHeader(u'=== ' + _(u'Empty %s Sublists') % list_label)
            for list_eid in sorted(removed_empty_sublists, key=unicode.lower):
                log(u'* ' + list_eid)
            log.setHeader(u'=== ' + _(u'Empty %s Sublists Removed') %
                          list_label)
            for list_eid in sorted(cleaned_lists, key=unicode.lower):
                log(u'* ' + list_eid)

    # Methods for patchers to override
    def _check_list(self, record, log):
        """Checks if any warnings for the specified list have to be logged.
        Default implementation does nothing."""

    def _get_entries(self, target_list):
        """Retrieves a list of the items in the specified list. No default
        implementation, every patcher needs to override this."""
        raise AbstractError()

class ListsMerger(_AListsMerger):
    """Merges leveled lists."""
    _read_write_records = bush.game.listTypes # bush.game must be set!
    _de_tag = u'Delev'
    _re_tag = u'Relev'
    _type_to_label = {
        'LVLC': _(u'Creature'),
        'LVLN': _(u'Actor'),
        'LVLI': _(u'Item'),
        'LVSP': _(u'Spell'),
    }
    _de_re_header = _(u'Delevelers/Relevelers')

    def __init__(self, p_name, p_file, p_sources, remove_empty, tag_choices):
        super(ListsMerger, self).__init__(p_name, p_file, p_sources,
                                          remove_empty, tag_choices)
        self.empties = set()
        _skip_id = lambda x: (GPath(bush.game.master_file), x)
        self._overhaul_compat(self.srcs, _skip_id)

    def _check_list(self, record, log):
        # Emit a warning for lists that may have exceeded 255 - note that
        # pre-Skyrim games have no size limit since they have no counter
        max_lvl_size = bush.game.Esp.max_lvl_list_size
        if max_lvl_size and len(record.entries) == max_lvl_size:
            log(u'  * __%s__' % _(u'Warning: Now has %u entries, may '
                                  u'have been truncated - check and '
                                  u'fix manually!') % max_lvl_size)

    def _get_entries(self, target_list):
        return [list_entry.listId for list_entry in target_list.entries]

#------------------------------------------------------------------------------
class FidListsMerger(_AListsMerger):
    """Merges FormID lists."""
    scanOrder = 46
    editOrder = 46
    _read_write_records = ('FLST',)
    _de_tag = u'Deflst'
    _type_to_label = {'FLST': _(u'FormID')}
    _de_re_header = _(u'Deflsters')

    def _get_entries(self, target_list):
        return target_list.formIDInList
