from volatility.plugins.windows.taskmods import DllList

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

    def render(self, data, ui):
        table = ui.table('Name', 'Pid', 'PPid', 'Thds', 'Hnds', 'Time', 'Virtual', 'Physical')
        for task in data:
            table.row(task.ImageFileName,
                      task.UniqueProcessId,
                      task.InheritedFromUniqueProcessId,
                      task.ActiveThreads,
                      task.ObjectTable.HandleCount,
                      task.CreateTime,
                      task.offset,
                      task.vm.vtop(task.offset))
