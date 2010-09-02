# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Original source:
# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
#
# Additional Authors:
# Michael Cohen <scudette@users.sourceforge.net>
# Mike Auty <mike.auty@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

#pylint: disable-msg=C0111

import os
import volatility.conf as conf
import volatility.commands as commands
import volatility.win32 as win32
import volatility.obj as obj
import volatility.utils as utils
import volatility.cache as cache

config = conf.ConfObject()

class DllList(commands.command, cache.Testable):
    """Print list of loaded dlls for each process"""

    def __init__(self, *args):
        config.add_option('OFFSET', short_option = 'o', default = None,
                          help = 'EPROCESS Offset (in hex) in kernel address space',
                          action = 'store', type = 'int')

        config.add_option('PID', short_option = 'p', default = None,
                          help = 'Operate on these Process IDs (comma-separated)',
                          action = 'store', type = 'str')

        commands.command.__init__(self, *args)
        cache.Testable.__init__(self, *args)

    def render_text(self, outfd, data):
        for task in data:
            pid = task.UniqueProcessId

            outfd.write("*" * 72 + "\n")
            outfd.write("{0} pid: {1:6}\n".format(task.ImageFileName, pid))

            if task.Peb:
                outfd.write("Command line : {0}\n".format(task.Peb.ProcessParameters.CommandLine))
                outfd.write("{0}\n".format(task.Peb.CSDVersion))
                outfd.write("\n")
                outfd.write("{0:12} {1:12} {2}\n".format('Base', 'Size', 'Path'))
                for m in self.list_modules(task):
                    outfd.write("0x{0:08x}   0x{1:06x}     {2}\n".format(m.DllBase, m.SizeOfImage, m.FullDllName))
            else:
                outfd.write("Unable to read PEB for task.\n")

    def list_modules(self, task):
        if task.UniqueProcessId and task.Peb.Ldr.InLoadOrderModuleList:
            for l in task.Peb.Ldr.InLoadOrderModuleList.list_of_type(
                "_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks"):
                yield l

    def filter_tasks(self, tasks):
        """ Reduce the tasks based on the user selectable PIDS parameter.

        Returns a reduced list or the full list if config.PIDS not specified.
        """
        try:
            if config.PID:
                pidlist = [int(p) for p in config.PID.split(',')]
                newtasks = [t for t in tasks if t.UniqueProcessId in pidlist]
                # Make this a separate statement, so that if an exception occurs, no harm done
                tasks = newtasks
        except (ValueError, TypeError):
            # TODO: We should probably print a non-fatal warning here
            pass

        return tasks

    @cache.CacheDecorator(lambda self: "tests/pslist/pid=%s" % self.config.PID)
    def calculate(self):
        """Produces a list of processes, or just a single process based on an OFFSET"""
        addr_space = utils.load_as()

        if config.OFFSET != None:
            tasks = [obj.Object("_EPROCESS", config.OFFSET, addr_space)]
        else:
            tasks = self.filter_tasks(win32.tasks.pslist(addr_space))

        return tasks

# Inherit from files just for the config options (__init__)
class Files(DllList):
    """Print list of open files for each process"""

    def __init__(self, *args):
        DllList.__init__(self, *args)
        self.handle_type = 'File'
        self.handle_obj = "_FILE_OBJECT"

    def render_text(self, outfd, data):
        first = True
        for pid, handles in data:
            if not first:
                outfd.write("*" * 72 + "\n")
            outfd.write("Pid: {0:6}\n".format(pid))
            first = False

            for h in handles:
                if h.FileName:
                    outfd.write("{0:6} {1:40}\n".format("File", h.FileName))

    def calculate(self):
        tasks = self.filter_tasks(DllList.calculate(self))

        for task in tasks:
            if task.ObjectTable.HandleTableList:
                pid = task.UniqueProcessId
                yield pid, self.handle_list(task)

    def handle_list(self, task):
        for h in task.handles():
            if str(h.Type.Name) == self.handle_type:
                yield obj.Object(self.handle_obj, h.Body.offset, task.vm, parent = task)

class PSList(DllList):
    """ print all running processes by following the EPROCESS lists """
    def render_text(self, outfd, data):
        outfd.write("{0:20} {1:6} {2:6} {3:6} {4:6} {5:6}\n".format(
            'Name', 'Pid', 'PPid', 'Thds', 'Hnds', 'Time'))

        for task in data:
            outfd.write("{0:20} {1:6} {2:6} {3:6} {4:6} {5:26}\n".format(
                task.ImageFileName,
                task.UniqueProcessId,
                task.InheritedFromUniqueProcessId,
                task.ActiveThreads,
                task.ObjectTable.HandleCount,
                task.CreateTime))

# Inherit from files just for the config options (__init__)
class MemMap(DllList):
    """Print the memory map"""

    def render_text(self, outfd, data):
        first = True
        for pid, task, pagedata in data:
            if not first:
                outfd.write("*" * 72 + "\n")

            task_space = task.get_process_address_space()
            outfd.write("{0} pid: {1:6}\n".format(task.ImageFileName, pid))
            first = False

            if pagedata:
                outfd.write("{0:12} {1:12} {2:12}\n".format('Virtual', 'Physical', 'Size'))

                for p in pagedata:
                    pa = task_space.vtop(p[0])
                    # pa can be 0, according to the old memmap, but can't == None(NoneObject)
                    if pa != None:
                        outfd.write("0x{0:010x} 0x{1:010x} 0x{2:012x}\n".format(p[0], pa, p[1]))
                    #else:
                    #    outfd.write("0x{0:10x} 0x000000     0x{1:12x}\n".format(p[0], p[1]))
            else:
                outfd.write("Unable to read pages for task.\n")

    @cache.CacheDecorator(lambda self: "test/memmap/pid%s" % self.config.PID)
    def calculate(self):
        tasks = self.filter_tasks(DllList.calculate(self))

        for task in tasks:
            if task.UniqueProcessId:
                pid = task.UniqueProcessId
                task_space = task.get_process_address_space()
                pages = task_space.get_available_pages()
                yield pid, task, pages

class MemDump(MemMap):
    """Dump the addressable memory for a process"""

    def __init__(self, *args):
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                          help = 'Directory in which to dump the VAD files')
        MemMap.__init__(self, *args)

    def render_text(self, outfd, data):
        if config.DUMP_DIR == None:
            config.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(config.DUMP_DIR):
            config.error(config.DUMP_DIR + " is not a directory")

        for pid, task, pagedata in data:
            outfd.write("*" * 72 + "\n")

            task_space = task.get_process_address_space()
            outfd.write("Writing {0} [{1:6}] to {2}.dmp\n".format(task.ImageFileName, pid, str(pid)))

            f = open(os.path.join(config.DUMP_DIR, str(pid) + ".dmp"), 'wb')
            if pagedata:
                for p in pagedata:
                    data = task_space.read(p[0], p[1])
                    f.write(data)
            else:
                outfd.write("Unable to read pages for task.\n")
            f.close()
