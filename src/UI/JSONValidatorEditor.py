from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.Qsci import QsciScintilla, QsciLexerJSON
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtCore import Qt, QTimer
import json
import sys

class JSONValidatorEditor(QsciScintilla):
    def __init__(self):
        super().__init__()
        self.setupEditor()
        self.error_marker_handle = None
        self.validation_timer = QTimer()
        self.validation_timer.setInterval(500)  # Validate after 500ms of inactivity
        self.validation_timer.timeout.connect(self.validateJSON)
        self.textChanged.connect(self.resetValidationTimer)
        
    def setupEditor(self):
        # Font configuration
        font = QFont("Consolas", 9)
        self.setFont(font)
        self.setWrapMode(QsciScintilla.WrapMode.WrapWord)
        
        # JSON Lexer with color scheme
        lexer = QsciLexerJSON()
        lexer.setDefaultFont(font)
        lexer.setColor(QColor("#c9184a"), 4)  # Property (keys) in light blue
        lexer.setColor(QColor("#CE9178"), 3)  # Strings in light orange
        lexer.setColor(QColor("#bc6c25"), 2)  # Numbers in soft green
        lexer.setColor(QColor("#569CD6"), 6)  # Operators in blue
        lexer.setColor(QColor("#C586C0"), 5)  # Keywords (true/false/null) in purple
        lexer.setColor(QColor("#D4D4D4"), 0)  # Default text
        self.setLexer(lexer)
        
        # Editor appearance
        self.setPaper(QColor("#1E1E1E"))
        self.setColor(QColor("#D4D4D4"))
        self.setMarginsFont(font)
        self.setMarginWidth(0, "0000")
        self.setMarginLineNumbers(0, True)
        #self.setCaretLineVisible(True)
        #self.setCaretLineBackgroundColor(QColor("#FFFF"))
        
        # Configure error indicators
        self.indicatorDefine(QsciScintilla.SquiggleIndicator, 0)
        self.setIndicatorForegroundColor(QColor("#FF5555"), 0)
        self.setIndicatorOutlineColor(QColor("#FF5555"), 0)
        
    def resetValidationTimer(self):
        self.validation_timer.stop()
        self.validation_timer.start()
        
    def validateJSON(self):
        self.validation_timer.stop()
        self.clearValidationErrors()
        
        try:
            json_data = json.loads(self.text())
            self.validateDataTypes(json_data)  # Additional type validation
        except json.JSONDecodeError as e:
            self.showJSONError(e)
            
    def clearValidationErrors(self):
        # Remove all error indicators
        self.clearIndicatorRange(0, 0, self.lines(), self.lineLength(self.lines()-1), 0)
        if self.error_marker_handle is not None:
            self.markerDeleteHandle(self.error_marker_handle)
            
    def showJSONError(self, error):
        # Highlight the error location
        error_line = error.lineno - 1
        error_col = error.colno - 1
        
        # Underline the error
        self.fillIndicatorRange(
            error_line, error_col,
            error_line, error_col + 10,  # Underline next 10 chars
            0
        )
        
        # Add error marker
        self.markerDefine(QsciScintilla.Circle, 0)
        self.setMarkerBackgroundColor(QColor("#FF5555"), 0)
        self.setMarkerForegroundColor(QColor("#FFFFFF"), 0)
        self.error_marker_handle = self.markerAdd(error_line, 0)
        
        # Show error in tooltip instead of status bar
        self.setToolTip(f"JSON Error: {error.msg}")

    def settext(self, data):
        if(data):
            self.setText(data)

    def validateDataTypes(self, data):
        """Recursively validate JSON data types"""
        if isinstance(data, dict):
            for key, value in data.items():
                if not isinstance(key, str):
                    self.showTypeError(f"Key '{key}' must be a string", self.getCursorPosition())
                self.validateDataTypes(value)
        elif isinstance(data, list):
            for item in data:
                self.validateDataTypes(item)
        elif not isinstance(data, (str, int, float, bool)) and data is not None:
            self.showTypeError(f"Invalid type: {type(data).__name__}", self.getCursorPosition())

    def showTypeError(self, message, position):
        # For simplicity, we'll just show a message box
        # In a real implementation, you would highlight the specific position
        QMessageBox.warning(self, "Type Error", message)

    def getCursorPosition(self):
        # Helper method to get current cursor position
        line, index = self.getCursorPosition()
        return (line, index)