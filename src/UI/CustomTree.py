import sys
from PyQt5.QtWidgets import QTreeWidget,QAbstractItemView, QMenu, QInputDialog, QTreeWidgetItem
from PyQt5.QtCore import Qt, pyqtSignal

class CustomTreeWidget(QTreeWidget):

    apply_signal = pyqtSignal(str) 
    rename_signal = pyqtSignal(str, QTreeWidgetItem) 
    delete_signal = pyqtSignal(str, QTreeWidgetItem) 
    drag_signal = pyqtSignal(QTreeWidgetItem) 
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setDragEnabled(True)
        self.setDragDropMode(QAbstractItemView.InternalMove)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.showContextMenu)
        
    def supportedDropActions(self):
        return Qt.MoveAction

    def dragMoveEvent(self, event):
        target_item = self.itemAt(event.pos())
        dragged_item = self.currentItem()
            
        if dragged_item and dragged_item.parent() is None:
            event.ignore()
            return
    
        if target_item and target_item.parent() is None:
            event.accept()
            return
            
        event.ignore()

    def startDrag(self, actions):
        item = self.currentItem()
        if item and item.parent():
            super().startDrag(actions)
        else:
            return
        
    def dropEvent(self, event):
        dragged_item = self.currentItem()
        super().dropEvent(event)

        # Check if the dragged item was a child item and if the drop was successful
        if dragged_item and dragged_item.parent() is not None:
            self.drag_signal.emit(dragged_item)
        
    def showContextMenu(self, pos):
        item = self.itemAt(pos)
        if item is None:
            return

        menu = QMenu(self)
        
        rename_action = menu.addAction("Rename")
        delete_action = menu.addAction("Delete")
        
        apply_action = None
        if item.parent() is not None:
            menu.addSeparator()
            apply_action = menu.addAction("Apply")
        
        action = menu.exec_(self.mapToGlobal(pos))
        
        if action == rename_action:
            self.renameItem(item)
        elif action == delete_action:
            self.deleteItem(item)
        elif action == apply_action:
            self.applyOption(item)

    def renameItem(self, item):
        new_name, ok = QInputDialog.getText(self, "Rename Item", "Enter new name:", text=item.text(0))
        if ok and new_name:
            item.setText(0, new_name)
            self.rename_signal.emit(str(new_name), item)

    def deleteItem(self, item):
        parent_item = item.parent()
        if parent_item:
            parent_item.removeChild(item)
        else:
            self.takeTopLevelItem(self.indexOfTopLevelItem(item))
        tab_id = item.data(0, Qt.UserRole)
        self.delete_signal.emit(str(tab_id), item)

    def applyOption(self, item):
        tab_id = item.data(0, Qt.UserRole)
        self.apply_signal.emit(str(tab_id))
