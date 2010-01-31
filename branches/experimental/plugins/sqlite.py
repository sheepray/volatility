""" This module implements SQLite support for volatility.

Based on code by Gleeda, adapted for 1.4beta:
http://gleeda.blogspot.com/2010/01/volatilitys-output-rendering-functions.html
"""
import volatility.commands as commands
import volatility.registry as registry
import volatility.debug as debug
import sqlite3, os

import volatility.conf as conf
config = conf.ConfObject()

config.add_option("SQLITE-FILENAME",
                  help = "SQLite database file to use")

def pslist_render(self, outfd, data):
    dbstring = config.SQLITE_FILENAME
    conn = sqlite3.connect(dbstring)
    cur = conn.cursor()

    try:
         cur.execute("select * from process")
    except sqlite3.OperationalError:
        cur.execute("create table process (pname text, pid integer, ppid integer, thrds integer, hndl integer, ctime text, memimage text)")
        conn.commit()

    for task in data:
        outfd.write("Dumped task @ 0x%X\n" % task.offset)
        cur.execute("insert into process values (?,?,?,?,?,?,?)",
                    (task.ImageFileName.v(),
                     task.UniqueProcessId.v(),
                     task.InheritedFromUniqueProcessId.v(),
                     int(task.ActiveThreads),
                     int(task.ObjectTable.HandleCount),
                     str(task.CreateTime),
                     config.FILENAME))
        conn.commit()

def connections_render(self, outfd, data):
    dbstring = config.SQLITE_FILENAME
    conn = sqlite3.connect(dbstring)
    cur = conn.cursor()

    try:
         cur.execute("select * from connections")
    except sqlite3.OperationalError:
        cur.execute("create table connections (pid integer, local text, local_port integer, remote text, remote_port integer, memimage text)")
        conn.commit()

    for connection in data:
        outfd.write("Dumped connection @ 0x%X\n" % connection.offset)
        cur.execute("insert into connections values (?,?,?,?,?,?)",
                    (connection.Pid.v(),
                     str(connection.LocalIpAddress),
                     int(connection.LocalPort),
                     str(connection.RemoteIpAddress),
                     int(connection.RemotePort),
                     config.FILENAME))
        conn.commit()

def sockets_render(self, outfd, data):
    conn = sqlite3.connect(config.SQLITE_FILENAME)
    cur = conn.cursor()

    try:
         cur.execute("select * from sockets")
    except sqlite3.OperationalError:
        cur.execute("create table sockets (pid integer, port integer, proto text, ctime text, memimage text)")
        conn.commit()

    for socket in data:
        outfd.write("Dumped socket @ 0x%X\n" % socket.offset)
        cur.execute("insert into sockets values (?,?,?,?,?)",
                    (int(socket.Pid),
                     int(socket.LocalPort),
                     int(socket.Protocol),
                     str(socket.CreateTime),
                     config.FILENAME))
        conn.commit()

def modules_render(self, outfd, data):
    conn = sqlite3.connect(config.SQLITE_FILENAME)
    cur = conn.cursor()

    try:
         cur.execute("select * from modules")
    except sqlite3.OperationalError:
        cur.execute("create table modules (file text, base text, size text, name text, memimage text)")
        conn.commit()

    for module in data:
        outfd.write("Dumped module @ 0x%X\n" % module.offset)
        cur.execute("insert into modules values (?,?,?,?,?)",
                    (str(module.FullDllName),
                     str(module.BaseAddress),
                     str(module.SizeOfImage),
                     str(module.ModuleName),
                     config.FILENAME))
        conn.commit()

def dlls_render(self, outfd, data):
    conn = sqlite3.connect(config.SQLITE_FILENAME)
    cur = conn.cursor()

    try:
         cur.execute("select * from dlls")
    except sqlite3.OperationalError:
        cur.execute("create table dlls (image_file_name text, pid integer, cmdline text, base text, size text, path text, memimage text)")
        conn.commit()

    for task in data:
        outfd.write("Dumped dlls for task @ 0x%X\n" % task.offset)
        if task.Peb:
            for m in self.list_modules(task):
                cur.execute("insert into dlls values (?,?,?,?,?,?,?)",
                            (str(task.ImageFileName),
                             int(task.UniqueProcessId),
                             str(task.Peb.ProcessParameters.CommandLine),
                             int(m.BaseAddress),
                             int(m.SizeOfImage),
                             str(m.FullDllName),
                             config.FILENAME))
        conn.commit()

def files_render(self, outfd, data):
    conn = sqlite3.connect(config.SQLITE_FILENAME)
    cur = conn.cursor()

    try:
         cur.execute("select * from files")
    except sqlite3.OperationalError:
        cur.execute("create table files (pid integer, file text, num integer, memimage text)")
        conn.commit()

    for pid, handles in data:
        pid = int(pid)
        for h in handles:
            cur.execute("select count(*) from files where pid = ? and file = ? and memimage = ?",
                        (pid, h.FileName.__str__(), config.FILENAME))
            count, = cur.fetchone()

            if count == 0:
                cur.execute("insert into files values (?,?,?,?)",
                            (pid, h.FileName.__str__(), 1, config.FILENAME))
            else:
                cur.execute("update files set num = ? where pid = ? and file = ? and memimage = ?", 
                            (count+1, pid, h.FileName.__str__(), config.FILENAME))
            conn.commit()

class SQLiteEvents(commands.EventHandler):
    def startup(self):
        registry.PLUGIN_COMMANDS.install_method("pslist", "render_sqlite", pslist_render)
        registry.PLUGIN_COMMANDS.install_method("connections",
                                                "render_sqlite", connections_render)
        registry.PLUGIN_COMMANDS.install_method("sockets", "render_sqlite", sockets_render)
        registry.PLUGIN_COMMANDS.install_method("modules", "render_sqlite", modules_render)
        registry.PLUGIN_COMMANDS.install_method("files", "render_sqlite", files_render)
        registry.PLUGIN_COMMANDS.install_method("dlllist", "render_sqlite", dlls_render)
