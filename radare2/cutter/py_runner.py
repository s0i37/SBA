import cutter

from PySide2.QtWidgets import QAction, QPushButton, QFileDialog

class MyDockWidget(cutter.CutterDockWidget):
    def __init__(self, parent, action):
        super(MyDockWidget, self).__init__(parent, action)
        self.setObjectName("MyDockWidget")
        self.setWindowTitle("Python")

        button = QPushButton("Run script")
        button.clicked.connect(self.choose_script)
        self.setWidget(button)

    def choose_script(self):
        path_to_file, _ = QFileDialog.getOpenFileName(self, "Choose script", "", "Python script (*.py)")
        print("[+] run %s" % path_to_file)
        with open(path_to_file) as f:
            exec(f.read(), globals())



class MyCutterPlugin(cutter.CutterPlugin):
    name = "Python script runner"
    description = "This plugin allows execute any python script"
    version = "0.1"
    author = "s0i37"

    def setupPlugin(self):
        pass

    def setupInterface(self, main):
        print("[*] %s %s" % (self.name, self.version))
        action = QAction("My Plugin", main)
        action.setCheckable(True)
        widget = MyDockWidget(main, action)
        main.addPluginDockWidget(widget, action)

    def terminate(self):
        pass

def create_cutter_plugin():
    return MyCutterPlugin()
